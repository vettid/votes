import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';

/** The Lambda's timeout: well under the minute between an extension's
 * checks and the results it must precede (docs/VOTES-SITE.md §4). */
export const LAMBDA_TIMEOUT_SECONDS = 20;

/** What the upload function may do on the bucket: read, list (so that a
 * missing object is a 404) and write. Never delete. */
export const BUCKET_ACTIONS = ['s3:GetObject', 's3:PutObject'] as const;

export interface VotesStackProps extends cdk.StackProps {
  readonly envName: string;
  /** votes.vettid.org, or the staging name. */
  readonly hostName: string;
  readonly hostedZoneId: string;
  readonly zoneName: string;
  /** The site's Ed25519 public key (base64), from `votesctl site-key`
   * after the first deploy. Until it is set, uploads are refused. */
  readonly siteKey?: string;
  /** The function's code; by default `cmd/votes-api` built for arm64. */
  readonly lambdaCode?: lambda.Code;
}

/** Builds cmd/votes-api for Lambda's provided.al2023 on arm64. */
function buildApi(): lambda.Code {
  const root = path.join(__dirname, '..', '..');
  return lambda.Code.fromAsset(root, {
    // The asset is named by what was built (a reproducible binary: no
    // build id, trimmed paths), not by the source tree it came from.
    assetHashType: cdk.AssetHashType.OUTPUT,
    exclude: ['cdk/node_modules', 'cdk/cdk.out', '.git'],
    bundling: {
      image: cdk.DockerImage.fromRegistry('unused'), // built locally, below
      local: {
        tryBundle(out: string): boolean {
          execFileSync('go', ['build', '-trimpath', '-ldflags=-s -w -buildid=', '-o', path.join(out, 'bootstrap'), './cmd/votes-api'], {
            cwd: root,
            env: { ...process.env, CGO_ENABLED: '0', GOOS: 'linux', GOARCH: 'arm64' },
            stdio: 'inherit',
          });
          return true;
        },
      },
    },
  });
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

    this.bucket = new s3.Bucket(this, 'Bucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

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
    this.fn = new lambda.Function(this, 'Api', {
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
        // Bundles are checked against the instance the service vaults
        // anchor in: staging outside production.
        VOTES_SIGSTORE: props.envName === 'prod' ? 'production' : 'staging',
        VOTES_SITE_KEY: props.siteKey ?? '',
      },
    });
    this.fn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'Objects', actions: [...BUCKET_ACTIONS], resources: [this.bucket.arnForObjects('*')],
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
    const apiDomain = cdk.Fn.select(2, cdk.Fn.split('/', api.apiEndpoint));
    this.distribution = new cloudfront.Distribution(this, 'Cdn', {
      comment: `votes.vettid.org (${props.envName})`,
      domainNames: [props.hostName],
      certificate: cert,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      // No access logs: the site keeps no record of readers (§5).
      enableLogging: false,
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(this.bucket),
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
        },
      },
    });
    const alias = route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(this.distribution));
    new route53.ARecord(this, 'AliasA', { zone, recordName: props.hostName, target: alias });
    new route53.AaaaRecord(this, 'AliasAAAA', { zone, recordName: props.hostName, target: alias });

    new cdk.CfnOutput(this, 'BucketName', { value: this.bucket.bucketName });
    new cdk.CfnOutput(this, 'SiteKeySecret', { value: siteKeySecret.secretArn });
    new cdk.CfnOutput(this, 'Url', { value: `https://${props.hostName}` });
  }
}
