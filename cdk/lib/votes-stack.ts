import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwactions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';

/** The Lambda's timeout: well under the minute between an extension's
 * checks and the results it must precede (docs/VOTES-SITE.md §4). */
export const LAMBDA_TIMEOUT_SECONDS = 20;

/** Where the upload function may write: published documents (write-once,
 * enforced by the bucket policy), the index and the archive. Not the
 * service list, which only the operator's votesctl writes. */
export const WRITE_PATHS = ['v1/p/*', 'v1/index.json', 'v1/archive/*'] as const;

/** The monitor's heartbeat (docs/VOTES-SITE.md §7): each run of
 * .github/workflows/monitor.yml that finds nothing wrong puts it, with the
 * dimension env; three hours without one raise the heartbeat alarm. */
export const HEARTBEAT = { namespace: 'VettID/Votes', metricName: 'MonitorHeartbeat', hours: 3 } as const;

/** What the monitor's role trusts: GitHub's OIDC tokens for the monitor
 * workflow of vettid/votes, run from main, for STS. */
export const MONITOR_OIDC = {
  issuer: 'token.actions.githubusercontent.com',
  audience: 'sts.amazonaws.com',
  sub: 'repo:vettid/votes:ref:refs/heads/main',
  jobWorkflowRef: 'vettid/votes/.github/workflows/monitor.yml@refs/heads/main',
} as const;

export interface VotesStackProps extends cdk.StackProps {
  readonly envName: string;
  /** votes.vettid.org, or the staging name. */
  readonly hostName: string;
  readonly hostedZoneId: string;
  readonly zoneName: string;
  /** The Sigstore instance bundles are checked against: the one the
   * service vaults of this environment anchor in (their SV_SIGSTORE). */
  readonly sigstore: 'staging' | 'production';
  /** The site's Ed25519 public key (base64), from `votesctl site-key`.
   * Absent only on the first deploy, which makes the key's secret: uploads
   * are refused until a deploy sets it. */
  readonly siteKey?: string;
  /** Recovery only, for one deploy with the owner's go: lets a key under
   * v1/services/ be deleted, to clear a stray object at a version's key
   * (README "Clearing a stray version copy"). The delete leaves a delete
   * marker: earlier object versions still can't be deleted, and puts
   * still need If-None-Match. The next deploy, without it, closes it. */
  readonly servicesRepair?: boolean;
  /** The SNS topic the monitor's alerts go to (docs/VOTES-SITE.md §7),
   * in the stack's region. With it, the stack makes the monitor's role,
   * which the workflow assumes through GitHub's OIDC provider to publish
   * a failed run there and to put its heartbeat, and the heartbeat's
   * alarm, which notifies the topic. Without it, neither. */
  readonly alarmTopicArn?: string;
  /** The account's existing OIDC provider for
   * token.actions.githubusercontent.com (an account has at most one, so
   * the stack takes it rather than making it). Required with
   * alarmTopicArn. */
  readonly githubOidcProviderArn?: string;
  /** The function's code; by default `cmd/votes-api` built for arm64. */
  readonly lambdaCode?: lambda.Code;
}

/** Builds cmd/votes-api with scripts/build-api.sh, the build CI runs and
 * hashes, so a deploy's binary can be compared with CI's. */
function buildApi(): lambda.Code {
  const root = path.join(__dirname, '..', '..');
  return lambda.Code.fromAsset(root, {
    // Named by what was built (reproducible), not by the source tree.
    assetHashType: cdk.AssetHashType.OUTPUT,
    exclude: ['cdk/node_modules', 'cdk/cdk.out', '.git'],
    bundling: {
      image: cdk.DockerImage.fromRegistry('unused'), // built locally, below
      local: {
        tryBundle(out: string): boolean {
          execFileSync(path.join(root, 'scripts', 'build-api.sh'), [out], { cwd: root, stdio: 'inherit' });
          return true;
        },
      },
    },
  });
}

/** A base64 Ed25519 public key: 32 bytes. */
export function validSiteKey(k: string): boolean {
  return /^[A-Za-z0-9+/]{43}=$/.test(k) && Buffer.from(k, 'base64').length === 32;
}

/**
 * votes.vettid.org (docs/VOTES-SITE.md §2): a private bucket read through
 * CloudFront, and the upload API (an HTTP API in front of a Lambda) under
 * /api on the same name.
 */
export class VotesStack extends cdk.Stack {
  readonly bucket: s3.Bucket;
  readonly fn: lambda.Function;
  readonly distribution: cloudfront.Distribution;

  constructor(scope: Construct, id: string, props: VotesStackProps) {
    super(scope, id, props);
    const prefix = `vettid-votes-${props.envName}`;
    if (props.siteKey !== undefined && !validSiteKey(props.siteKey)) {
      throw new Error('siteKey must be a base64 Ed25519 public key (votesctl site-key)');
    }
    if (!cdk.Token.isUnresolved(this.region) && this.region !== 'us-east-1') {
      throw new Error('the stack must be in us-east-1: CloudFront takes its certificate from there');
    }

    this.bucket = new s3.Bucket(this, 'Bucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // Write-once, enforced by S3 for every principal: a published document,
    // and each kept version of the service list, is written only with
    // If-None-Match: * and never deleted (§2). The current list
    // (v1/services.json and .sig) is outside both and is replaced in place.
    const writeOnce = [this.bucket.arnForObjects('v1/p/*'), this.bucket.arnForObjects('v1/services/*')];
    this.bucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'PublishedWriteOnce', effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()],
      actions: ['s3:PutObject'], resources: writeOnce,
      conditions: { Null: { 's3:if-none-match': 'true' } },
    }));
    const repair = props.servicesRepair === true;
    this.bucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'PublishedNeverDeleted', effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()],
      actions: ['s3:DeleteObject', 's3:DeleteObjectVersion'],
      resources: repair ? [this.bucket.arnForObjects('v1/p/*')] : writeOnce,
    }));
    if (repair) {
      // A delete only hides a stray: its object versions stay.
      this.bucket.addToResourcePolicy(new iam.PolicyStatement({
        sid: 'ServicesRepairKeepsVersions', effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()],
        actions: ['s3:DeleteObjectVersion'], resources: [this.bucket.arnForObjects('v1/services/*')],
      }));
      cdk.Annotations.of(this).addWarning('servicesRepair: keys under v1/services/ can be deleted until the next deploy without it');
    }

    // The site's signing key for the service list: a generated secret the
    // operator's votesctl derives the key from. The function never reads
    // it: it gets the public key (siteKey).
    const siteKeySecret = new secretsmanager.Secret(this, 'SiteKey', {
      secretName: `${prefix}/site-key`,
      description: 'Seed of the site key that signs the service list (votesctl)',
      generateSecretString: { passwordLength: 64, excludePunctuation: true, includeSpace: false },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const logGroup = new logs.LogGroup(this, 'ApiLogs', {
      logGroupName: `/vettid/votes/${props.envName}/api`,
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // The function's own role, with no managed policy: it may write its
    // log group and touch its bucket, and nothing else in the account.
    const role = new iam.Role(this, 'ApiRole', {
      roleName: `${prefix}-api`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'Logs', actions: ['logs:CreateLogStream', 'logs:PutLogEvents'], resources: [logGroup.logGroupArn], // its Arn ends in :*, covering its streams
    }));
    this.fn = new lambda.Function(this, 'Api', {
      role,
      functionName: `${prefix}-api`,
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: props.lambdaCode ?? buildApi(),
      memorySize: 256,
      timeout: cdk.Duration.seconds(LAMBDA_TIMEOUT_SECONDS),
      logGroup,
      environment: {
        VOTES_BUCKET: this.bucket.bucketName,
        VOTES_SIGSTORE: props.sigstore,
        VOTES_SITE_KEY: props.siteKey ?? '',
      },
    });
    this.fn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'Read', actions: ['s3:GetObject'], resources: [this.bucket.arnForObjects('*')],
    }));
    this.fn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'Write', actions: ['s3:PutObject'], resources: WRITE_PATHS.map((p) => this.bucket.arnForObjects(p)),
    }));
    this.fn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'List', actions: ['s3:ListBucket'], resources: [this.bucket.bucketArn],
    }));

    const api = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: `${prefix}-api`,
      createDefaultStage: false,
    });
    api.addRoutes({
      path: '/api/v1/p/{id}/{name}',
      methods: [apigwv2.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('Upload', this.fn),
    });
    new apigwv2.HttpStage(this, 'Stage', {
      httpApi: api,
      stageName: '$default',
      autoDeploy: true,
      throttle: { rateLimit: 10, burstLimit: 20 },
    });

    const zone = route53.HostedZone.fromHostedZoneAttributes(this, 'Zone', {
      hostedZoneId: props.hostedZoneId, zoneName: props.zoneName,
    });
    const cert = new acm.Certificate(this, 'Cert', {
      domainName: props.hostName, validation: acm.CertificateValidation.fromDns(zone),
    });
    const headers = new cloudfront.ResponseHeadersPolicy(this, 'Headers', {
      responseHeadersPolicyName: `${prefix}-headers`,
      securityHeadersBehavior: {
        strictTransportSecurity: { accessControlMaxAge: cdk.Duration.days(730), includeSubdomains: true, preload: true, override: true },
        contentTypeOptions: { override: true },
        frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },
        referrerPolicy: { referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER, override: true },
      },
      // The documents are public: observers may read them from a page of
      // their own.
      corsBehavior: {
        accessControlAllowOrigins: ['*'], accessControlAllowMethods: ['GET', 'HEAD'],
        accessControlAllowHeaders: ['*'], accessControlAllowCredentials: false, originOverride: true,
      },
    });
    const apiHeaders = new cloudfront.ResponseHeadersPolicy(this, 'ApiHeaders', {
      responseHeadersPolicyName: `${prefix}-api-headers`,
      securityHeadersBehavior: {
        strictTransportSecurity: { accessControlMaxAge: cdk.Duration.days(730), includeSubdomains: true, preload: true, override: true },
        contentTypeOptions: { override: true },
        frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },
        referrerPolicy: { referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER, override: true },
      },
    });
    const apiDomain = cdk.Fn.select(2, cdk.Fn.split('/', api.apiEndpoint));
    this.distribution = new cloudfront.Distribution(this, 'Cdn', {
      comment: `votes.vettid.org (${props.envName})`,
      domainNames: [props.hostName],
      certificate: cert,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      // No access logs: the site keeps no record of readers (§5).
      enableLogging: false,
      defaultBehavior: {
        // LIST as well as READ, so that a missing document is a 404.
        origin: origins.S3BucketOrigin.withOriginAccessControl(this.bucket, {
          originAccessLevels: [cloudfront.AccessLevel.READ, cloudfront.AccessLevel.LIST],
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: headers,
      },
      additionalBehaviors: {
        '/api/*': {
          origin: new origins.HttpOrigin(apiDomain),
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
          responseHeadersPolicy: apiHeaders,
        },
      },
    });
    // Every document is public, and the default cache policy forwards no
    // query string, so LIST gives readers 404s rather than 403s and no
    // listing.
    cdk.Annotations.of(this.distribution).acknowledgeWarning(
      '@aws-cdk/aws-cloudfront-origins:listBucketSecurityRisk', 'all documents are public; no query string reaches S3');
    const alias = route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(this.distribution));
    new route53.ARecord(this, 'AliasA', { zone, recordName: props.hostName, target: alias });
    new route53.AaaaRecord(this, 'AliasAAAA', { zone, recordName: props.hostName, target: alias });

    if (props.alarmTopicArn !== undefined || props.githubOidcProviderArn !== undefined) {
      this.monitorAlerts(prefix, props);
    }

    new cdk.CfnOutput(this, 'BucketName', { value: this.bucket.bucketName });
    new cdk.CfnOutput(this, 'SiteKeySecret', { value: siteKeySecret.secretArn });
    new cdk.CfnOutput(this, 'DistributionId', { value: this.distribution.distributionId });
    new cdk.CfnOutput(this, 'Url', { value: `https://${props.hostName}` });
  }

  /** The monitor's role and its heartbeat alarm (docs/VOTES-SITE.md §7). */
  private monitorAlerts(prefix: string, props: VotesStackProps): void {
    const topicArn = props.alarmTopicArn;
    const providerArn = props.githubOidcProviderArn;
    if (topicArn === undefined || providerArn === undefined) {
      throw new Error('set both alarmTopicArn and githubOidcProviderArn, or neither: the heartbeat alarm needs the role that puts the heartbeat');
    }
    const arn = /^arn:aws[a-z-]*:sns:([a-z0-9-]+):[0-9]{12}:[A-Za-z0-9_-]+$/.exec(topicArn);
    if (!arn) throw new Error(`alarmTopicArn must be an SNS topic ARN (got "${topicArn}")`);
    if (!cdk.Token.isUnresolved(this.region) && arn[1] !== this.region) {
      throw new Error(`alarmTopicArn must be in the stack's region, ${this.region}: a CloudWatch alarm notifies a topic in its own region (got ${arn[1]})`);
    }
    if (!/^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider\/token\.actions\.githubusercontent\.com$/.test(providerArn)) {
      throw new Error(`githubOidcProviderArn must be the ARN of the account's token.actions.githubusercontent.com OIDC provider (got "${providerArn}")`);
    }
    const topic = sns.Topic.fromTopicArn(this, 'AlarmTopic', topicArn);
    const provider = iam.OpenIdConnectProvider.fromOpenIdConnectProviderArn(this, 'GitHubOidc', providerArn);
    const iss = MONITOR_OIDC.issuer;
    const role = new iam.Role(this, 'MonitorRole', {
      roleName: `${prefix}-monitor`,
      description: 'votesctl check -all, hourly (.github/workflows/monitor.yml): alerts and heartbeat only',
      maxSessionDuration: cdk.Duration.hours(1),
      assumedBy: new iam.OpenIdConnectPrincipal(provider, {
        StringEquals: {
          [`${iss}:aud`]: MONITOR_OIDC.audience,
          [`${iss}:sub`]: MONITOR_OIDC.sub,
          [`${iss}:job_workflow_ref`]: MONITOR_OIDC.jobWorkflowRef,
        },
      }),
    });
    role.addToPolicy(new iam.PolicyStatement({ sid: 'Alert', actions: ['sns:Publish'], resources: [topicArn] }));
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'Heartbeat', actions: ['cloudwatch:PutMetricData'], resources: ['*'], // it has no resource-level ARN
      conditions: { StringEquals: { 'cloudwatch:namespace': HEARTBEAT.namespace } },
    }));
    // One run an hour: an hour's sum is 1, or 0 when a run failed (it
    // alerts on its own) or none ran. Missing data breaches, so a schedule
    // GitHub disabled, or runs that can't reach AWS, raise it too.
    const heartbeat = new cloudwatch.Metric({
      namespace: HEARTBEAT.namespace, metricName: HEARTBEAT.metricName, dimensionsMap: { env: props.envName },
      statistic: cloudwatch.Stats.SUM, period: cdk.Duration.hours(1),
    });
    const alarm = new cloudwatch.Alarm(this, 'MonitorHeartbeatAlarm', {
      alarmName: `${prefix}-monitor-heartbeat`,
      alarmDescription: `No successful monitor run for ${props.envName} in ${HEARTBEAT.hours} hours (docs/VOTES-SITE.md §7)`,
      metric: heartbeat,
      threshold: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      evaluationPeriods: HEARTBEAT.hours,
      datapointsToAlarm: HEARTBEAT.hours,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });
    alarm.addAlarmAction(new cwactions.SnsAction(topic));
    alarm.addOkAction(new cwactions.SnsAction(topic));
    new cdk.CfnOutput(this, 'MonitorRoleArn', { value: role.roleArn });
  }
}
