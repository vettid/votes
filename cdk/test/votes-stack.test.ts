import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { HEARTBEAT, LAMBDA_TIMEOUT_SECONDS, MONITOR_OIDC, VotesStack, validSiteKey } from '../lib/votes-stack';

// A fixed public test value, not a real key: 32 bytes of 0x07.
const SITE_KEY = Buffer.alloc(32, 7).toString('base64');

type Extra = { siteKey?: string; region?: string; servicesRepair?: boolean; alarmTopicArn?: string; githubOidcProviderArn?: string };
function stack(envName: string, sigstore: 'staging' | 'production', extra: Extra = {}): VotesStack {
  const app = new cdk.App();
  return new VotesStack(app, `VotesSite-${envName}`, {
    envName, hostName: 'votes.example.org', hostedZoneId: 'Z123', zoneName: 'example.org', sigstore,
    siteKey: 'siteKey' in extra ? extra.siteKey : SITE_KEY,
    servicesRepair: extra.servicesRepair,
    alarmTopicArn: extra.alarmTopicArn,
    githubOidcProviderArn: extra.githubOidcProviderArn,
    lambdaCode: lambda.Code.fromAsset(path.join(__dirname, 'fake-api')),
    env: { account: '123456789012', region: extra.region ?? 'us-east-1' },
  });
}
const synth = (envName: string, sigstore: 'staging' | 'production') => Template.fromStack(stack(envName, sigstore));

const t = synth('staging', 'staging');

const asList = (v: unknown): any[] => (Array.isArray(v) ? v : [v]);
function fnStatements(): any[] {
  const roles = t.findResources('AWS::IAM::Policy');
  return Object.values(roles).flatMap((p: any) => p.Properties.PolicyDocument.Statement);
}

describe('bucket', () => {
  test('private, versioned, encrypted, TLS only, retained', () => {
    t.hasResource('AWS::S3::Bucket', {
      DeletionPolicy: 'Retain',
      Properties: Match.objectLike({
        VersioningConfiguration: { Status: 'Enabled' },
        PublicAccessBlockConfiguration: { BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true },
      }),
    });
  });

  test('published documents and service-list versions: written only with If-None-Match, never deleted, for every principal', () => {
    const p = Object.values(t.findResources('AWS::S3::BucketPolicy'))[0] as any;
    const st: any[] = p.Properties.PolicyDocument.Statement;
    const once = st.find((x) => x.Sid === 'PublishedWriteOnce');
    expect(once).toMatchObject({ Effect: 'Deny', Principal: { AWS: '*' }, Action: 's3:PutObject',
      Condition: { Null: { 's3:if-none-match': 'true' } } });
    const keep = st.find((x) => x.Sid === 'PublishedNeverDeleted');
    expect(keep).toMatchObject({ Effect: 'Deny', Principal: { AWS: '*' } });
    expect(keep.Action).toEqual(expect.arrayContaining(['s3:DeleteObject', 's3:DeleteObjectVersion']));
    // Proposals' documents and the kept versions of the service list; not
    // the current list, which a publish replaces with If-Match.
    for (const r of [once.Resource, keep.Resource]) {
      const paths = JSON.stringify(r);
      expect(paths).toContain('/v1/p/*');
      expect(paths).toContain('/v1/services/*');
      expect(paths).not.toContain('services.json');
      expect(r).toHaveLength(2);
    }
    expect(st.find((x) => x.Sid === 'ServicesRepairKeepsVersions')).toBeUndefined();
  });

  test('servicesRepair: a key under v1/services/ can be deleted, its versions cannot, puts stay conditional', () => {
    const s = stack('staging', 'staging', { servicesRepair: true });
    const p = Object.values(Template.fromStack(s).findResources('AWS::S3::BucketPolicy'))[0] as any;
    const st: any[] = p.Properties.PolicyDocument.Statement;
    const once = st.find((x) => x.Sid === 'PublishedWriteOnce');
    expect(JSON.stringify(once.Resource)).toContain('/v1/services/*');
    const keep = st.find((x) => x.Sid === 'PublishedNeverDeleted');
    expect(JSON.stringify(keep.Resource)).toContain('/v1/p/*');
    expect(JSON.stringify(keep.Resource)).not.toContain('/v1/services/');
    expect(keep.Action).toEqual(expect.arrayContaining(['s3:DeleteObject', 's3:DeleteObjectVersion']));
    const versions = st.find((x) => x.Sid === 'ServicesRepairKeepsVersions');
    expect(versions).toMatchObject({ Effect: 'Deny', Principal: { AWS: '*' }, Action: 's3:DeleteObjectVersion' });
    expect(JSON.stringify(versions.Resource)).toContain('/v1/services/*');
    const warn = s.node.metadata.filter((m) => m.type === 'aws:cdk:warning').map((m) => String(m.data));
    expect(warn.join(' ')).toContain('servicesRepair');
  });
});

describe('upload function', () => {
  test('arm64, provided.al2023, a timeout well under the minute', () => {
    t.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'provided.al2023', Architectures: ['arm64'], Handler: 'bootstrap', Timeout: LAMBDA_TIMEOUT_SECONDS,
    });
    expect(LAMBDA_TIMEOUT_SECONDS).toBeLessThan(45);
  });

  test('staging checks bundles against Sigstore staging, prod against production', () => {
    t.hasResourceProperties('AWS::Lambda::Function', {
      Environment: { Variables: Match.objectLike({ VOTES_SIGSTORE: 'staging', VOTES_SITE_KEY: SITE_KEY }) },
    });
    synth('prod', 'production').hasResourceProperties('AWS::Lambda::Function', {
      Environment: { Variables: Match.objectLike({ VOTES_SIGSTORE: 'production' }) },
    });
  });

  test('may read and list the bucket; never delete; no secret', () => {
    const actions = fnStatements().flatMap((s) => asList(s.Action));
    expect(actions).toEqual(expect.arrayContaining(['s3:GetObject', 's3:PutObject', 's3:ListBucket']));
    expect(actions.filter((a: string) => a.startsWith('s3:Delete') || a === 's3:*')).toEqual([]);
    expect(actions.filter((a: string) => a.startsWith('secretsmanager:'))).toEqual([]);
  });

  test('its own role: no managed policy, logs only to its log group', () => {
    const roles = Object.values(t.findResources('AWS::IAM::Role')) as any[];
    expect(roles).toHaveLength(1);
    expect(roles[0].Properties.ManagedPolicyArns).toBeUndefined();
    const res = fnStatements().flatMap((s) => asList(s.Resource));
    expect(res).not.toContain('*');
    const logs = fnStatements().filter((s) => asList(s.Action).some((a: string) => a.startsWith('logs:')));
    expect(logs).toHaveLength(1);
    expect(JSON.stringify(logs[0].Resource)).toContain('ApiLogs');
  });

  test('writes only documents, the index and the archive: never the service list', () => {
    const w = fnStatements().filter((s) => asList(s.Action).includes('s3:PutObject'));
    const res = JSON.stringify(w.map((s) => s.Resource));
    for (const p of ['/v1/p/*', '/v1/index.json', '/v1/archive/*']) expect(res).toContain(p);
    expect(res).not.toContain('services');
    expect(res).not.toMatch(/"\/\*"/);
  });

  test('refuses a site key that is not 32 bytes of base64, and a region other than us-east-1', () => {
    expect(validSiteKey(SITE_KEY)).toBe(true);
    expect(validSiteKey('c2l0ZWtleQ==')).toBe(false);
    expect(() => stack('x', 'staging', { siteKey: 'c2l0ZWtleQ==' })).toThrow(/siteKey/);
    expect(() => stack('x', 'staging', { region: 'eu-west-1' })).toThrow(/us-east-1/);
    expect(() => stack('x', 'staging', { siteKey: undefined })).not.toThrow();
  });
});

describe('edge', () => {
  test('the upload route only, throttled', () => {
    t.resourceCountIs('AWS::ApiGatewayV2::Route', 1);
    t.hasResourceProperties('AWS::ApiGatewayV2::Route', { RouteKey: 'POST /api/v1/p/{id}/{name}' });
    t.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
      StageName: '$default', DefaultRouteSettings: { ThrottlingRateLimit: 10, ThrottlingBurstLimit: 20 },
    });
  });

  test('security headers on /api', () => {
    t.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
      ResponseHeadersPolicyConfig: Match.objectLike({ SecurityHeadersConfig: Match.objectLike({
        ContentTypeOptions: { Override: true }, FrameOptions: { FrameOption: 'DENY', Override: true } }) }),
    });
  });

  test('no access logs; documents through origin access control; /api to the API', () => {
    const d = Object.values(t.findResources('AWS::CloudFront::Distribution'))[0] as any;
    const c = d.Properties.DistributionConfig;
    expect(c.Logging).toBeUndefined();
    expect(c.Aliases).toEqual(['votes.example.org']);
    expect(c.CacheBehaviors.map((b: any) => b.PathPattern)).toEqual(['/api/*']);
    t.resourceCountIs('AWS::CloudFront::OriginAccessControl', 1);
  });

  test('the site key secret is retained', () => {
    t.hasResource('AWS::SecretsManager::Secret', { DeletionPolicy: 'Retain' });
  });
});

describe('monitor alerts', () => {
  // Fixed test values: no real account.
  const TOPIC = 'arn:aws:sns:us-east-1:123456789012:vettid-alarms';
  const PROVIDER = 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com';
  const m = Template.fromStack(stack('staging', 'staging', { alarmTopicArn: TOPIC, githubOidcProviderArn: PROVIDER }));
  const monitorRole = (): any => {
    const roles = Object.values(m.findResources('AWS::IAM::Role')) as any[];
    const r = roles.filter((x) => x.Properties.RoleName === 'vettid-votes-staging-monitor');
    expect(r).toHaveLength(1);
    return r[0];
  };
  const monitorStatements = (): any[] => {
    const policies = Object.values(m.findResources('AWS::IAM::Policy')) as any[];
    const mine = policies.filter((p) => JSON.stringify(p.Properties.Roles).includes('MonitorRole'));
    expect(mine).toHaveLength(1);
    return mine[0].Properties.PolicyDocument.Statement;
  };

  test('without a topic: no monitor role and no alarm', () => {
    expect((Object.values(t.findResources('AWS::IAM::Role')) as any[]).map((r) => r.Properties.RoleName)).toEqual(['vettid-votes-staging-api']);
    t.resourceCountIs('AWS::CloudWatch::Alarm', 0);
  });

  test('the role trusts only the monitor workflow of vettid/votes on main, through the given provider, for STS', () => {
    const doc = monitorRole().Properties.AssumeRolePolicyDocument;
    expect(doc.Statement).toHaveLength(1);
    const st = doc.Statement[0];
    expect(st).toMatchObject({ Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity', Principal: { Federated: PROVIDER } });
    expect(st.Condition).toEqual({ StringEquals: {
      'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
      'token.actions.githubusercontent.com:sub': 'repo:vettid/votes:ref:refs/heads/main',
      'token.actions.githubusercontent.com:job_workflow_ref': 'vettid/votes/.github/workflows/monitor.yml@refs/heads/main',
    } });
    expect(MONITOR_OIDC.sub).toBe('repo:vettid/votes:ref:refs/heads/main');
    // No provider is made: the account's is taken.
    m.resourceCountIs('Custom::AWSCDKOpenIdConnectProvider', 0);
    m.resourceCountIs('AWS::IAM::OIDCProvider', 0);
    expect(monitorRole().Properties.ManagedPolicyArns).toBeUndefined();
  });

  test('the role may publish to the topic and put the heartbeat, nothing else', () => {
    const st = monitorStatements();
    expect(st).toHaveLength(2);
    expect(st.find((x) => x.Sid === 'Alert')).toEqual({ Sid: 'Alert', Effect: 'Allow', Action: 'sns:Publish', Resource: TOPIC });
    expect(st.find((x) => x.Sid === 'Heartbeat')).toEqual({ Sid: 'Heartbeat', Effect: 'Allow', Action: 'cloudwatch:PutMetricData', Resource: '*',
      Condition: { StringEquals: { 'cloudwatch:namespace': 'VettID/Votes' } } });
  });

  test('the heartbeat alarm: three hours without a successful run, missing data breaching, to the topic', () => {
    m.resourceCountIs('AWS::CloudWatch::Alarm', 1);
    m.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmName: 'vettid-votes-staging-monitor-heartbeat',
      Namespace: HEARTBEAT.namespace, MetricName: 'MonitorHeartbeat', Dimensions: [{ Name: 'env', Value: 'staging' }],
      Statistic: 'Sum', Period: 3600, EvaluationPeriods: 3, DatapointsToAlarm: 3,
      Threshold: 1, ComparisonOperator: 'LessThanThreshold', TreatMissingData: 'breaching',
      AlarmActions: [TOPIC], OKActions: [TOPIC],
    });
  });

  test('refuses half a configuration, a topic elsewhere, and a provider that is not GitHub\'s', () => {
    expect(() => stack('x', 'staging', { alarmTopicArn: TOPIC })).toThrow(/both/);
    expect(() => stack('x', 'staging', { githubOidcProviderArn: PROVIDER })).toThrow(/both/);
    expect(() => stack('x', 'staging', { alarmTopicArn: 'arn:aws:sns:eu-west-1:123456789012:a', githubOidcProviderArn: PROVIDER })).toThrow(/region/);
    expect(() => stack('x', 'staging', { alarmTopicArn: 'vettid-alarms', githubOidcProviderArn: PROVIDER })).toThrow(/SNS topic ARN/);
    expect(() => stack('x', 'staging', { alarmTopicArn: TOPIC,
      githubOidcProviderArn: 'arn:aws:iam::123456789012:oidc-provider/accounts.google.com' })).toThrow(/githubOidcProviderArn/);
  });
});
