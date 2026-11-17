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
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';

/** The Lambda's timeout: well under the minute between an extension's
 * checks and the results it must precede (docs/VOTES-SITE.md §4). */
export const LAMBDA_TIMEOUT_SECONDS = 20;

/** Where the upload function may write: published documents (write-once,
 * enforced by the bucket policy), the index and the archive. Not the
 * service list, which only the operator's votesctl writes. */
export const WRITE_PATHS = ['v1/p/*', 'v1/index.json', 'v1/archive/*'] as const;

/** The monitor's heartbeat (docs/VOTES-SITE.md §7): each run of
 * .github/workflows/monitor.yml that finds nothing wrong puts it in its
 * environment's namespace (`VettID/Votes/<env>`, so one environment's role
 * can't put another's), with the dimension env; three hours without one
 * raise the heartbeat alarm. */
export const HEARTBEAT = { namespacePrefix: 'VettID/Votes/', metricName: 'MonitorHeartbeat', hours: 3 } as const;

/** heartbeatNamespace is an environment's heartbeat namespace. */
export function heartbeatNamespace(envName: string): string { return HEARTBEAT.namespacePrefix + envName; }

/** What the monitor's role trusts: GitHub's OIDC tokens for the monitor
 * workflow of vettid/votes, run from main, for STS. The repository uses
 * GitHub's immutable subjects (owner and repository ids with the names,
 * `gh api repos/vettid/votes/actions/oidc/customization/sub`), so `sub`
 * carries them; a renamed or recreated repository does not match. */
export const MONITOR_OIDC = {
  issuer: 'token.actions.githubusercontent.com',
  audience: 'sts.amazonaws.com',
  sub: 'repo:vettid@168311946/votes@1438447065:ref:refs/heads/main',
  jobWorkflowRef: 'vettid/votes/.github/workflows/monitor.yml@refs/heads/main',
} as const;

/** The WAF's per-address rule on uploads: at most this many requests
 * under /api/ from one IP address in API_RATE_WINDOW_SECONDS, beyond
 * which they are blocked (docs/VOTES-SITE.md §4, "Limits"). */
export const API_RATE_LIMIT = 100;
export const API_RATE_WINDOW_SECONDS = 300;

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
   * in the stack's region, required: the stack makes the monitor's role,
   * which the workflow assumes through GitHub's OIDC provider to publish
   * a failed run there and to put its heartbeat, and the heartbeat's
   * alarm, which notifies the topic; and the site keys' alarms go there
   * too. */
  readonly alarmTopicArn?: string;
  /** The account's existing OIDC provider for
   * token.actions.githubusercontent.com (an account has at most one, so
   * the stack takes it rather than making it). Required with
   * alarmTopicArn. */
  readonly githubOidcProviderArn?: string;
  /** Where the key watch's own topic sends each watched event, directly
   * from EventBridge with no alarm in the path: an email address the owner
   * confirms once (from the email AWS sends). It is in the deployed
   * template, never in the repository. */
  readonly keyWatchEmail: string;
  /** The role of the IAM Identity Center permission set the operator
   * signs in with to publish (its own set, assigned to the owner alone,
   * whose only permission is assuming the publish role; sign-in requires
   * MFA): the only principal that may assume the publish role, which alone
   * may sign with the site's KMS keys (VOTE-SITE-KEY-COMPROMISE §6, GC
   * #12646, #12713). */
  readonly publisherPrincipalArn: string;
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

/** The KMS operations on the site's keys (or their aliases) that are
 * watched: every signature, and every change that could let someone else
 * sign (a grant, a new key policy, an alias pointed elsewhere) or end the
 * key. */
export const KEY_USE_EVENTS = ['Sign', 'CreateGrant', 'PutKeyPolicy', 'ScheduleKeyDeletion', 'DisableKey',
  'CreateAlias', 'UpdateAlias', 'DeleteAlias'] as const;

/** The IAM operations on the publish role that are watched: a change to
 * who may assume it or what it may do. */
export const PUBLISH_ROLE_EVENTS = ['UpdateAssumeRolePolicy', 'PutRolePolicy', 'DeleteRolePolicy', 'AttachRolePolicy',
  'DetachRolePolicy', 'PutRolePermissionsBoundary', 'DeleteRolePermissionsBoundary', 'UpdateRole', 'DeleteRole'] as const;

/** The operations on the watch itself that are watched, so that it can't
 * be switched off unseen: by the API that makes them, and what each is
 * matched on (the watch's own resource, or any). */
export const WATCH_EVENTS = {
  // Its rules and their targets, by rule name.
  rules: ['DisableRule', 'DeleteRule', 'PutRule', 'RemoveTargets', 'PutTargets'],
  // Its alarms, by alarm name.
  alarms: ['DisableAlarmActions', 'EnableAlarmActions', 'DeleteAlarms', 'PutMetricAlarm', 'SetAlarmState'],
  // Its log group, by name.
  logGroup: ['DeleteLogGroup', 'PutRetentionPolicy', 'DeleteRetentionPolicy', 'DeleteMetricFilter', 'PutMetricFilter',
    'DeleteLogStream', 'AssociateKmsKey', 'DisassociateKmsKey'],
  // Any log group resource policy: the one that lets the rules write is
  // per account, by name.
  logPolicies: ['PutResourcePolicy', 'DeleteResourcePolicy'],
  // Any trail: the watch gets every event from CloudTrail.
  trails: ['StopLogging', 'StartLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'PutAdvancedEventSelectors'],
  // Its topics (the alarm topic and its own), and their subscriptions.
  topics: ['Subscribe', 'ConfirmSubscription', 'Unsubscribe', 'SetSubscriptionAttributes', 'SetTopicAttributes', 'DeleteTopic',
    'AddPermission', 'RemovePermission', 'PutDataProtectionPolicy'],
  // Its dead letters.
  queue: ['PurgeQueue', 'DeleteQueue', 'SetQueueAttributes', 'AddPermission', 'RemovePermission'],
  // Any alarm mute rule (one can name the watch's alarms).
  muteRules: ['PutAlarmMuteRule', 'DeleteAlarmMuteRule'],
  // This stack, by name or ARN: one update can change all of the watch.
  stack: ['UpdateStack', 'DeleteStack', 'CreateChangeSet', 'ExecuteChangeSet', 'SetStackPolicy',
    'UpdateTerminationProtection', 'ContinueUpdateRollback', 'CancelUpdateStack'],
} as const;

/** The role of an IAM Identity Center permission set, as
 * publisherPrincipalArn must be (GC #12713: a set of its own, assigned to
 * the owner alone, whose assignment list is the access list):
 * arn:aws:iam::<account>:role/aws-reserved/sso.amazonaws.com/[<region>/]AWSReservedSSO_<set>_<16 hex>. */
export function validRoleArn(a: string): boolean {
  return /^arn:aws[a-z-]*:iam::[0-9]{12}:role\/aws-reserved\/sso\.amazonaws\.com\/([a-z0-9-]+\/)?AWSReservedSSO_[\w+=,.@-]{1,32}_[0-9a-f]{16}$/.test(a);
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
  readonly webAcl: wafv2.CfnWebACL;

  constructor(scope: Construct, id: string, props: VotesStackProps) {
    super(scope, id, props);
    const prefix = `vettid-votes-${props.envName}`;
    if (props.siteKey !== undefined && !validSiteKey(props.siteKey)) {
      throw new Error('siteKey must be a base64 Ed25519 public key (votesctl site-key)');
    }
    if (!validRoleArn(props.publisherPrincipalArn)) {
      throw new Error(`publisherPrincipalArn must be the role of an IAM Identity Center permission set (…:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_<set>_<hash>; got "${props.publisherPrincipalArn}")`);
    }
    const publisherAccount = props.publisherPrincipalArn.split(':')[4];
    if (!cdk.Token.isUnresolved(this.account) && publisherAccount !== this.account) {
      throw new Error(`publisherPrincipalArn must be a role of this account, ${this.account} (got ${publisherAccount})`);
    }
    // The site keys can sign, so their watch must reach a person: both
    // the alarm topic and the watch's own email.
    if (props.alarmTopicArn === undefined) {
      throw new Error('alarmTopicArn (and githubOidcProviderArn) are required: the site keys\' alarms go there');
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(props.keyWatchEmail ?? '')) {
      throw new Error('keyWatchEmail must be an email address: the key watch notifies it directly');
    }
    // The watch is in this stack, so deleting it is refused until this
    // is turned off (a watched call).
    this.terminationProtection = true;
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
    // AWS WAF in front of CloudFront (scope CLOUDFRONT, which must be in
    // us-east-1, as this stack is): one rate rule per source address on
    // uploads; everything else passes. The stage throttle above is for the
    // whole API; this keeps one address from taking all of it. Metrics
    // only, no request sampling or logging: the site keeps no record of
    // readers (§5).
    this.webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      name: `${prefix}-web-acl`,
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      customResponseBodies: { rateLimited: { contentType: 'APPLICATION_JSON', content: '{"error":"rate_limited"}' } },
      visibilityConfig: { cloudWatchMetricsEnabled: true, metricName: `${prefix}-web-acl`, sampledRequestsEnabled: false },
      rules: [{
        name: 'ApiRatePerIp',
        priority: 0,
        // 429, not WAF's default 403: a client (the service vault's
        // publisher) retries a 429 and takes a 403 as a final refusal.
        action: { block: { customResponse: { responseCode: 429, customResponseBodyKey: 'rateLimited' } } },
        statement: {
          rateBasedStatement: {
            limit: API_RATE_LIMIT,
            evaluationWindowSec: API_RATE_WINDOW_SECONDS,
            aggregateKeyType: 'IP',
            scopeDownStatement: {
              byteMatchStatement: {
                fieldToMatch: { uriPath: {} },
                positionalConstraint: 'STARTS_WITH',
                searchString: '/api/',
                // As CloudFront routes it: decoded, then with dot
                // segments and repeated slashes removed, so /%61pi/,
                // /./api/, /v1/../api/ and //api/ are all counted.
                textTransformations: [{ priority: 0, type: 'URL_DECODE' }, { priority: 1, type: 'NORMALIZE_PATH' }],
              },
            },
          },
        },
        visibilityConfig: { cloudWatchMetricsEnabled: true, metricName: `${prefix}-api-rate`, sampledRequestsEnabled: false },
      }],
    });

    const apiDomain = cdk.Fn.select(2, cdk.Fn.split('/', api.apiEndpoint));
    this.distribution = new cloudfront.Distribution(this, 'Cdn', {
      comment: `votes.vettid.org (${props.envName})`,
      domainNames: [props.hostName],
      certificate: cert,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      // No access logs: the site keeps no record of readers (§5).
      enableLogging: false,
      webAclId: this.webAcl.attrArn,
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
    // After monitorAlerts, which checks alarmTopicArn.
    this.siteKeys(prefix, props);

    new cdk.CfnOutput(this, 'BucketName', { value: this.bucket.bucketName });
    new cdk.CfnOutput(this, 'SiteKeySecret', { value: siteKeySecret.secretArn });
    new cdk.CfnOutput(this, 'DistributionId', { value: this.distribution.distributionId });
    new cdk.CfnOutput(this, 'Url', { value: `https://${props.hostName}` });
  }

  /**
   * The site's signing keys, made inside KMS so that they can never be
   * exported (VOTE-SITE-KEY-COMPROMISE §6, GC #12646): the site key
   * (Ed25519) that signs the service list, and the list anchor key
   * (ECDSA P-256) that logs each list in Rekor. Only the publish role may
   * sign with them, and only publisherPrincipalArn may assume it. Every
   * signature, and every change that could let anyone else sign or
   * silence the watch, goes directly to two watch topics (emailed) and to
   * a log group, and raises an alarm on the alarm topic and both.
   */
  private siteKeys(prefix: string, props: VotesStackProps): void {
    const publish = new iam.Role(this, 'PublishRole', {
      roleName: `${prefix}-publish`,
      description: 'votesctl publish-services: signs the service list with the site keys and writes it',
      maxSessionDuration: cdk.Duration.hours(1),
      assumedBy: new iam.ArnPrincipal(props.publisherPrincipalArn),
    });
    // The list and its kept versions, and nothing else in the bucket. The
    // bucket policy still makes the kept versions write-once.
    publish.addToPolicy(new iam.PolicyStatement({
      sid: 'ServiceList', actions: ['s3:GetObject', 's3:PutObject'],
      resources: ['v1/services.json', 'v1/services.json.sig', 'v1/services/*'].map((k) => this.bucket.arnForObjects(k)),
    }));
    // So that a missing copy is a 404, not a 403. Without a prefix
    // condition: S3's own check for that has no prefix, and every
    // document in the bucket is public anyway.
    publish.addToPolicy(new iam.PolicyStatement({
      sid: 'ServiceListList', actions: ['s3:ListBucket'], resources: [this.bucket.bucketArn],
    }));

    const root = new iam.AccountRootPrincipal();
    // `Administer` is the account's: any principal of the account whose
    // IAM policies allow these (an account administrator) may use them,
    // PutKeyPolicy included, so that the keys can't be locked out. Such a
    // change is watched below. No one gets Sign that way.
    const policy = (algorithm: string): iam.PolicyDocument => new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: 'Administer', principals: [root], resources: ['*'],
          actions: ['kms:Create*', 'kms:Describe*', 'kms:Enable*', 'kms:List*', 'kms:Put*', 'kms:Update*', 'kms:Revoke*',
            'kms:Disable*', 'kms:Get*', 'kms:Delete*', 'kms:TagResource', 'kms:UntagResource',
            'kms:ScheduleKeyDeletion', 'kms:CancelKeyDeletion', 'kms:Verify'],
        }),
        new iam.PolicyStatement({
          sid: 'PublishRoleSigns', principals: [publish], resources: ['*'],
          actions: ['kms:Sign'], conditions: { StringEquals: { 'kms:SigningAlgorithm': algorithm } },
        }),
        new iam.PolicyStatement({
          sid: 'PublishRoleReads', principals: [publish], resources: ['*'],
          actions: ['kms:GetPublicKey', 'kms:DescribeKey'],
        }),
        new iam.PolicyStatement({
          sid: 'OnlyThePublishRoleSigns', effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()], resources: ['*'],
          actions: ['kms:Sign'], conditions: { ArnNotEquals: { 'aws:PrincipalArn': publish.roleArn } },
        }),
        // A grant would let another principal sign without a policy change.
        new iam.PolicyStatement({
          sid: 'NoGrants', effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()], resources: ['*'],
          actions: ['kms:CreateGrant'],
        }),
        new iam.PolicyStatement({
          sid: 'OnlyRootDeletes', effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()], resources: ['*'],
          actions: ['kms:ScheduleKeyDeletion'], conditions: { ArnNotEquals: { 'aws:PrincipalArn': root.arn } },
        }),
      ],
    });
    const siteAlias = `${prefix}-site`;
    const anchorAlias = `${prefix}-list-anchor`;
    const site = new kms.Key(this, 'SiteSigningKey', {
      alias: siteAlias,
      description: 'The votes site key (Ed25519): signs the service list (votesctl publish-services)',
      keySpec: kms.KeySpec.ECC_NIST_EDWARDS25519,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      policy: policy('ED25519_SHA_512'),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pendingWindow: cdk.Duration.days(30),
    });
    const listAnchor = new kms.Key(this, 'ListAnchorKey', {
      alias: anchorAlias,
      description: 'The votes list anchor key (ECDSA P-256): logs each service list in Rekor (votesctl publish-services)',
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      policy: policy('ECDSA_SHA_256'),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pendingWindow: cdk.Duration.days(30),
    });
    const aliasArn = (name: string): string =>
      this.formatArn({ service: 'kms', resource: 'alias', arnFormat: cdk.ArnFormat.SLASH_RESOURCE_NAME, resourceName: name });

    // Every watched event goes, from CloudTrail through EventBridge, to a
    // log group kept for good and, directly, to the watch's own topic, so
    // that no alarm sits between an event and a person. Each line has the
    // operation, the key or role, the caller's identity type, role and
    // temporary key id (traceable to its AssumeRole) and the CloudTrail
    // event id; never the session name (an Identity Center session is
    // named by an email address).
    const keyUse = new logs.LogGroup(this, 'KeyUseLogs', {
      logGroupName: `/vettid/votes/${props.envName}/key-use`,
      retention: logs.RetentionDays.INFINITE,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // Two watch topics, each with its own subscription, so that a
    // subscription removed or a topic changed on one is told on the other
    // directly, whatever state the alarms are in.
    const watchTopics = ['', '-b'].map((suffix, i) => {
      const topic = new sns.Topic(this, i === 0 ? 'KeyWatchTopic' : 'KeyWatchTopicB', {
        topicName: `${prefix}-key-watch${suffix}`,
        displayName: `VettID votes key watch${suffix} (${props.envName})`,
        enforceSSL: true,
      });
      topic.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
      const sub = new sns.Subscription(this, i === 0 ? 'KeyWatchEmail' : 'KeyWatchEmailB', {
        topic, protocol: sns.SubscriptionProtocol.EMAIL, endpoint: props.keyWatchEmail,
      });
      sub.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
      // The alarms below publish here too.
      topic.addToResourcePolicy(new iam.PolicyStatement({
        sid: 'Alarms', principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')], actions: ['sns:Publish'],
        resources: [topic.topicArn], conditions: { StringEquals: { 'aws:SourceAccount': this.account } },
      }));
      return topic;
    });
    // votesctl checks before a publish that both subscriptions are
    // confirmed (it reads them; it can't change them).
    publish.addToPolicy(new iam.PolicyStatement({
      sid: 'KeyWatchSubscriptions', actions: ['sns:ListSubscriptionsByTopic'], resources: watchTopics.map((t) => t.topicArn),
    }));
    const alarmTopicArn = props.alarmTopicArn as string;
    const alarmTopic = sns.Topic.fromTopicArn(this, 'KeyUseTopic', alarmTopicArn);
    // Deliveries that fail after EventBridge's retries land here, and
    // raise the feed alarm: a silent feed must not look like no use.
    const deadLetters = new sqs.Queue(this, 'KeyUseDeadLetters', {
      queueName: `${prefix}-key-use-dlq`,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: cdk.Duration.days(14),
    });
    const ruleNames = [`${prefix}-key-use`, `${prefix}-key-use-b`];
    const alarmNames = [`${prefix}-key-use`, `${prefix}-key-use-feed`];
    const policyName = `${prefix}-key-use`;
    const topicArns = [alarmTopicArn, ...watchTopics.map((t) => t.topicArn)];
    const stackArnPrefix = `arn:${this.partition}:cloudformation:${this.region}:${this.account}:stack/${this.stackName}/`;
    const pattern = {
      detailType: ['AWS API Call via CloudTrail'],
      detail: {
        $or: [
          { eventSource: ['kms.amazonaws.com'], eventName: [...KEY_USE_EVENTS],
            resources: { ARN: [site.keyArn, listAnchor.keyArn, aliasArn(siteAlias), aliasArn(anchorAlias)] } },
          { eventSource: ['iam.amazonaws.com'], eventName: [...PUBLISH_ROLE_EVENTS], requestParameters: { roleName: [publish.roleName] } },
          { eventSource: ['events.amazonaws.com'], eventName: [...WATCH_EVENTS.rules], requestParameters: { name: ruleNames } },
          { eventSource: ['events.amazonaws.com'], eventName: [...WATCH_EVENTS.rules], requestParameters: { rule: ruleNames } },
          { eventSource: ['monitoring.amazonaws.com'], eventName: [...WATCH_EVENTS.alarms], requestParameters: { alarmNames } },
          { eventSource: ['monitoring.amazonaws.com'], eventName: [...WATCH_EVENTS.alarms], requestParameters: { alarmName: alarmNames } },
          { eventSource: ['logs.amazonaws.com'], eventName: [...WATCH_EVENTS.logGroup], requestParameters: { logGroupName: [keyUse.logGroupName] } },
          { eventSource: ['logs.amazonaws.com'], eventName: [...WATCH_EVENTS.logPolicies] },
          { eventSource: ['cloudtrail.amazonaws.com'], eventName: [...WATCH_EVENTS.trails] },
          { eventSource: ['sns.amazonaws.com'], eventName: [...WATCH_EVENTS.topics], requestParameters: { topicArn: topicArns } },
          // PutDataProtectionPolicy names its topic as resourceArn.
          { eventSource: ['sns.amazonaws.com'], eventName: [...WATCH_EVENTS.topics], requestParameters: { resourceArn: topicArns } },
          { eventSource: ['sns.amazonaws.com'], eventName: [...WATCH_EVENTS.topics],
            requestParameters: { subscriptionArn: topicArns.map((t) => ({ prefix: `${t}:` })) } },
          { eventSource: ['sqs.amazonaws.com'], eventName: [...WATCH_EVENTS.queue], requestParameters: { queueUrl: [deadLetters.queueUrl] } },
          // Any alarm mute rule: one can name the watch's alarms.
          { eventSource: ['monitoring.amazonaws.com'], eventName: [...WATCH_EVENTS.muteRules] },
          // This stack: one update can change every part of the watch.
          { eventSource: ['cloudformation.amazonaws.com'], eventName: [...WATCH_EVENTS.stack], requestParameters: { stackName: [this.stackName] } },
          { eventSource: ['cloudformation.amazonaws.com'], eventName: [...WATCH_EVENTS.stack], requestParameters: { stackName: [{ prefix: stackArnPrefix }] } },
        ],
      },
    };
    const f = (path: string): string => events.EventField.fromPath(path);
    // What it acted on: the key, or the name its API gives (only one is
    // present for any event).
    const line = f('$.detail.eventSource') + ' ' + f('$.detail.eventName') + ' ' + f('$.detail.resources[0].ARN') +
      f('$.detail.requestParameters.roleName') + f('$.detail.requestParameters.name') + f('$.detail.requestParameters.rule') +
      f('$.detail.requestParameters.alarmName') + f('$.detail.requestParameters.topicArn') + f('$.detail.requestParameters.subscriptionArn') +
      f('$.detail.requestParameters.resourceArn') + f('$.detail.requestParameters.logGroupName') + f('$.detail.requestParameters.stackName') +
      f('$.detail.requestParameters.queueUrl') + ' by ' + f('$.detail.userIdentity.type') + ' ' +
      f('$.detail.userIdentity.sessionContext.sessionIssuer.arn') + ' key ' + f('$.detail.userIdentity.accessKeyId') +
      ' error ' + f('$.detail.errorCode') + ' event ' + f('$.detail.eventID');
    const logTarget = this.formatArn({ service: 'logs', resource: 'log-group', arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME, resourceName: keyUse.logGroupName });
    const retry = { maximumRetryAttempts: 185, maximumEventAgeInSeconds: 86400 };
    // Two rules with the same pattern and targets: each sees a change to
    // the other, so switching one off is seen (every event is logged and
    // sent twice).
    const rules = ruleNames.map((ruleName, i) => {
      const rule = new events.Rule(this, i === 0 ? 'KeyUseRule' : 'KeyUseRuleB', {
        ruleName,
        description: 'The votes site keys: every signature, and every change that could let someone else sign or silence this',
        eventPattern: pattern,
      });
      rule.addTarget({
        bind: () => ({
          arn: logTarget,
          deadLetterConfig: { arn: deadLetters.queueArn },
          retryPolicy: retry,
          input: events.RuleTargetInput.fromObject({ timestamp: events.EventField.time, message: line }),
        }),
      });
      // Bound by hand (not the SnsTopic target), so that the topic policy
      // lets only these rules publish (below).
      for (const topic of watchTopics) {
        rule.addTarget({
          bind: () => ({
            arn: topic.topicArn,
            deadLetterConfig: { arn: deadLetters.queueArn },
            retryPolicy: retry,
            input: events.RuleTargetInput.fromText(`VettID votes key watch (${props.envName}): ` + line),
          }),
        });
      }
      rule.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
      // Sign may count as a read-only management event, which a rule gets
      // only in this state (not settable through the Rule construct).
      (rule.node.defaultChild as events.CfnRule).addPropertyOverride('State', 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS');
      return rule;
    });
    const fromRules = { ArnEquals: { 'aws:SourceArn': rules.map((r) => r.ruleArn) } };
    // Only these rules may write to the log group, the dead letters or the
    // watch topics. The log group's is set here rather than by the
    // CloudWatchLogGroup target, which would add a Lambda to set it.
    for (const topic of watchTopics) {
      topic.addToResourcePolicy(new iam.PolicyStatement({
        sid: 'Rules', principals: [new iam.ServicePrincipal('events.amazonaws.com')], actions: ['sns:Publish'],
        resources: [topic.topicArn], conditions: fromRules,
      }));
    }
    new logs.ResourcePolicy(this, 'KeyUseLogsPolicy', {
      resourcePolicyName: policyName,
      policyStatements: [new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal('events.amazonaws.com')],
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'], resources: [keyUse.logGroupArn],
        conditions: fromRules,
      })],
    });
    deadLetters.addToResourcePolicy(new iam.PolicyStatement({
      principals: [new iam.ServicePrincipal('events.amazonaws.com')],
      actions: ['sqs:SendMessage'], resources: [deadLetters.queueArn],
      conditions: fromRules,
    }));

    // The alarms, to every topic: the alarm topic and the watch's two (so
    // silencing one path is told on another).
    // Not the heartbeat's namespace, which the monitor's role may put
    // metrics in; and SampleCount, not Sum, so that a value anyone puts
    // there can only raise the alarm, never hide a use.
    const namespace = `VettID/VotesKeys/${props.envName}`;
    new logs.MetricFilter(this, 'KeyUseMetric', {
      filterName: policyName, logGroup: keyUse, filterPattern: logs.FilterPattern.allEvents(),
      metricNamespace: namespace, metricName: 'KeyUse', metricValue: '1',
    });
    const alarm = new cloudwatch.Alarm(this, 'KeyUseAlarm', {
      alarmName: alarmNames[0],
      alarmDescription: `A votes site key of ${props.envName}, its publish role or this watch was used or changed: see ${keyUse.logGroupName}. ` +
        'A publish raises it (two signatures, each logged twice: four lines); a publish that does not means the feed is broken: stop and check it.',
      metric: new cloudwatch.Metric({ namespace, metricName: 'KeyUse', statistic: cloudwatch.Stats.SAMPLE_COUNT, period: cdk.Duration.minutes(1) }),
      threshold: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    // The feed: a failed delivery, or one in the dead letters. Each term
    // is filled with 0 when it has no data, so that one with data counts.
    const failed = new cloudwatch.MathExpression({
      label: 'failed deliveries and dead letters',
      expression: 'FILL(f0, 0) + FILL(f1, 0) + FILL(d, 0)',
      usingMetrics: {
        f0: new cloudwatch.Metric({ namespace: 'AWS/Events', metricName: 'FailedInvocations', dimensionsMap: { RuleName: ruleNames[0] }, statistic: cloudwatch.Stats.SUM, period: cdk.Duration.minutes(5) }),
        f1: new cloudwatch.Metric({ namespace: 'AWS/Events', metricName: 'FailedInvocations', dimensionsMap: { RuleName: ruleNames[1] }, statistic: cloudwatch.Stats.SUM, period: cdk.Duration.minutes(5) }),
        d: deadLetters.metricApproximateNumberOfMessagesVisible({ statistic: cloudwatch.Stats.MAXIMUM, period: cdk.Duration.minutes(5) }),
      },
      period: cdk.Duration.minutes(5),
    });
    const feed = new cloudwatch.Alarm(this, 'KeyUseFeedAlarm', {
      alarmName: alarmNames[1],
      alarmDescription: `The key watch of ${props.envName} failed to deliver: uses of the votes site keys may be missing from ${keyUse.logGroupName} and its emails. ` +
        `Read the dead letters in ${deadLetters.queueName}, then purge them: the alarm stays in ALARM while any remain.`,
      metric: failed,
      threshold: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    for (const a of [alarm, feed]) {
      a.addAlarmAction(new cwactions.SnsAction(alarmTopic));
      for (const topic of watchTopics) a.addAlarmAction(new cwactions.SnsAction(topic));
    }

    new cdk.CfnOutput(this, 'SiteSigningKeyArn', { value: site.keyArn });
    new cdk.CfnOutput(this, 'ListAnchorKeyArn', { value: listAnchor.keyArn });
    new cdk.CfnOutput(this, 'PublishRoleArn', { value: publish.roleArn });
    new cdk.CfnOutput(this, 'KeyWatchTopicArn', { value: watchTopics[0].topicArn });
    new cdk.CfnOutput(this, 'KeyWatchTopicBArn', { value: watchTopics[1].topicArn });
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
      conditions: { StringEquals: { 'cloudwatch:namespace': heartbeatNamespace(props.envName) } },
    }));
    // One run an hour: an hour's sum is 1, or 0 when a run failed (it
    // alerts on its own) or none ran. Missing data breaches, so a schedule
    // GitHub disabled, or runs that can't reach AWS, raise it too.
    const heartbeat = new cloudwatch.Metric({
      namespace: heartbeatNamespace(props.envName), metricName: HEARTBEAT.metricName, dimensionsMap: { env: props.envName },
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
