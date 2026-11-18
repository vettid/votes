import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { API_RATE_LIMIT, API_RATE_WINDOW_SECONDS, HEARTBEAT, heartbeatNamespace, KEY_USE_EVENTS, KEY_WATCH_HEARTBEAT_HOURS, KEY_WATCH_PATTERN_MAX, LAMBDA_TIMEOUT_SECONDS, MONITOR_OIDC, PUBLISH_ROLE_EVENTS, VotesStack, validRoleArn, validSiteKey, WATCH_EVENTS } from '../lib/votes-stack';

// A fixed public test value, not a real key: 32 bytes of 0x07.
const SITE_KEY = Buffer.alloc(32, 7).toString('base64');

// The operator's role, as an IAM Identity Center role ARN looks (a test value).
const PUBLISHER = 'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Operator_0123456789abcdef';

// Fixed test values: no real account, topic or address.
const TOPIC = 'arn:aws:sns:us-east-1:123456789012:vettid-alarms';
const PROVIDER = 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com';
const EMAIL = 'keys@example.org';

type Extra = { siteKey?: string; region?: string; servicesRepair?: boolean; alarmTopicArn?: string; githubOidcProviderArn?: string;
  publisherPrincipalArn?: string; keyWatchEmail?: string };
function stack(envName: string, sigstore: 'staging' | 'production', extra: Extra = {}): VotesStack {
  const app = new cdk.App();
  return new VotesStack(app, `VotesSite-${envName}`, {
    envName, hostName: 'votes.example.org', hostedZoneId: 'Z123', zoneName: 'example.org', sigstore,
    siteKey: 'siteKey' in extra ? extra.siteKey : SITE_KEY,
    servicesRepair: extra.servicesRepair,
    alarmTopicArn: 'alarmTopicArn' in extra ? extra.alarmTopicArn : TOPIC,
    githubOidcProviderArn: 'githubOidcProviderArn' in extra ? extra.githubOidcProviderArn : PROVIDER,
    publisherPrincipalArn: extra.publisherPrincipalArn ?? PUBLISHER,
    keyWatchEmail: 'keyWatchEmail' in extra ? extra.keyWatchEmail as string : EMAIL,
    lambdaCode: lambda.Code.fromAsset(path.join(__dirname, 'fake-api')),
    env: { account: '123456789012', region: extra.region ?? 'us-east-1' },
  });
}
const synth = (envName: string, sigstore: 'staging' | 'production') => Template.fromStack(stack(envName, sigstore));

const t = synth('staging', 'staging');

const asList = (v: unknown): any[] => (Array.isArray(v) ? v : [v]);
function fnStatements(): any[] {
  const roles = t.findResources('AWS::IAM::Policy');
  return Object.values(roles).filter((p: any) => JSON.stringify(p.Properties.Roles).includes('ApiRole'))
    .flatMap((p: any) => p.Properties.PolicyDocument.Statement);
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
    // The function's, the monitor's, the publish role and the key watch
    // heartbeat's (site keys, below); no other, and none with a managed
    // policy (no helper Lambda either: the only other function is the key
    // watch heartbeat's).
    const roles = Object.values(t.findResources('AWS::IAM::Role')) as any[];
    expect(roles.map((r) => r.Properties.RoleName).sort()).toEqual(['vettid-votes-staging-api', 'vettid-votes-staging-key-watch-heartbeat',
      'vettid-votes-staging-monitor', 'vettid-votes-staging-publish']);
    for (const r of roles) expect(r.Properties.ManagedPolicyArns).toBeUndefined();
    const fns = Object.values(t.findResources('AWS::Lambda::Function')) as any[];
    expect(fns.map((f) => f.Properties.FunctionName).sort()).toEqual(['vettid-votes-staging-api', 'vettid-votes-staging-key-watch-heartbeat']);
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

  test('a WAF web ACL for CloudFront: allow by default, metrics on, no sampled requests', () => {
    t.resourceCountIs('AWS::WAFv2::WebACL', 1);
    t.hasResourceProperties('AWS::WAFv2::WebACL', {
      Scope: 'CLOUDFRONT',
      DefaultAction: { Allow: {} },
      VisibilityConfig: Match.objectLike({ CloudWatchMetricsEnabled: true, SampledRequestsEnabled: false }),
    });
  });

  test('its one rule: 100 requests per 5 minutes per IP under /api/, then blocked with 429', () => {
    expect(API_RATE_LIMIT).toBe(100);
    expect(API_RATE_WINDOW_SECONDS).toBe(300);
    const acl = Object.values(t.findResources('AWS::WAFv2::WebACL'))[0] as any;
    const rules: any[] = acl.Properties.Rules;
    expect(rules).toHaveLength(1);
    expect(acl.Properties.CustomResponseBodies).toEqual({ rateLimited: { ContentType: 'APPLICATION_JSON', Content: '{"error":"rate_limited"}' } });
    expect(rules[0]).toMatchObject({
      Action: { Block: { CustomResponse: { ResponseCode: 429, CustomResponseBodyKey: 'rateLimited' } } },
      VisibilityConfig: { CloudWatchMetricsEnabled: true },
      Statement: { RateBasedStatement: { Limit: 100, EvaluationWindowSec: 300, AggregateKeyType: 'IP' } },
    });
  });

  test('the rule is scoped down to URI paths starting with /api/, decoded and normalized first', () => {
    const acl = Object.values(t.findResources('AWS::WAFv2::WebACL'))[0] as any;
    const scope = acl.Properties.Rules[0].Statement.RateBasedStatement.ScopeDownStatement;
    expect(scope).toEqual({
      ByteMatchStatement: {
        FieldToMatch: { UriPath: {} },
        PositionalConstraint: 'STARTS_WITH',
        SearchString: '/api/',
        TextTransformations: [{ Priority: 0, Type: 'URL_DECODE' }, { Priority: 1, Type: 'NORMALIZE_PATH' }],
      },
    });
  });

  test('the distribution is behind the web ACL', () => {
    const acls = Object.keys(t.findResources('AWS::WAFv2::WebACL'));
    const d = Object.values(t.findResources('AWS::CloudFront::Distribution'))[0] as any;
    expect(d.Properties.DistributionConfig.WebACLId).toEqual({ 'Fn::GetAtt': [acls[0], 'Arn'] });
  });

  test('the site key secret is retained', () => {
    t.hasResource('AWS::SecretsManager::Secret', { DeletionPolicy: 'Retain' });
  });
});

describe('monitor alerts', () => {
  const m = t;
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

  test('the topic and the provider are required (the site keys\' alarms go there too)', () => {
    expect(() => stack('x', 'staging', { alarmTopicArn: undefined, githubOidcProviderArn: undefined })).toThrow(/alarmTopicArn/);
  });

  test('the role trusts only the monitor workflow of vettid/votes on main, through the given provider, for STS', () => {
    const doc = monitorRole().Properties.AssumeRolePolicyDocument;
    expect(doc.Statement).toHaveLength(1);
    const st = doc.Statement[0];
    expect(st).toMatchObject({ Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity', Principal: { Federated: PROVIDER } });
    expect(st.Condition).toEqual({ StringEquals: {
      'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
      'token.actions.githubusercontent.com:sub': 'repo:vettid@168311946/votes@1438447065:ref:refs/heads/main',
      'token.actions.githubusercontent.com:job_workflow_ref': 'vettid/votes/.github/workflows/monitor.yml@refs/heads/main',
    } });
    expect(MONITOR_OIDC.sub).toBe('repo:vettid@168311946/votes@1438447065:ref:refs/heads/main');
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
      Condition: { StringEquals: { 'cloudwatch:namespace': 'VettID/Votes/staging' } } });
    // The key watch's heartbeat is its function's role's, not this one's.
    expect(JSON.stringify(st)).not.toContain('kms:');
    expect(monitorRole().Properties.Policies).toBeUndefined();
  });

  test('the heartbeat alarm: twelve hours without a successful run, missing data breaching, to the topic', () => {
    m.resourceCountIs('AWS::CloudWatch::Alarm', 4); // and the key-use, feed and key watch heartbeat alarms (site keys, below)
    m.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmName: 'vettid-votes-staging-monitor-heartbeat',
      Namespace: heartbeatNamespace('staging'), MetricName: 'MonitorHeartbeat', Dimensions: [{ Name: 'env', Value: 'staging' }],
      Statistic: 'Sum', Period: 3600, EvaluationPeriods: 12, DatapointsToAlarm: 12,
      Threshold: 1, ComparisonOperator: 'LessThanThreshold', TreatMissingData: 'breaching',
      AlarmActions: [TOPIC], OKActions: [TOPIC],
    });
  });

  test('refuses half a configuration, a topic elsewhere, and a provider that is not GitHub\'s', () => {
    expect(() => stack('x', 'staging', { alarmTopicArn: TOPIC, githubOidcProviderArn: undefined })).toThrow(/both/);
    expect(() => stack('x', 'staging', { alarmTopicArn: undefined, githubOidcProviderArn: PROVIDER })).toThrow(/alarmTopicArn/);
    expect(() => stack('x', 'staging', { alarmTopicArn: 'arn:aws:sns:eu-west-1:123456789012:a', githubOidcProviderArn: PROVIDER })).toThrow(/region/);
    expect(() => stack('x', 'staging', { alarmTopicArn: 'vettid-alarms', githubOidcProviderArn: PROVIDER })).toThrow(/SNS topic ARN/);
    expect(() => stack('x', 'staging', { alarmTopicArn: TOPIC,
      githubOidcProviderArn: 'arn:aws:iam::123456789012:oidc-provider/accounts.google.com' })).toThrow(/githubOidcProviderArn/);
  });
});

describe('site keys (VOTE-SITE-KEY-COMPROMISE §6)', () => {
  const keys = t.findResources('AWS::KMS::Key');
  const byUse = (spec: string): any => Object.values(keys).find((k: any) => k.Properties.KeySpec === spec) as any;
  const logical = (type: string, re: RegExp): string => {
    const ks = Object.keys(t.findResources(type)).filter((k) => re.test(k));
    expect(ks).toHaveLength(1);
    return ks[0];
  };
  const publishLogical = Object.keys(t.findResources('AWS::IAM::Role', { Properties: { RoleName: 'vettid-votes-staging-publish' } }))[0];
  const bucketLogical = Object.keys(t.findResources('AWS::S3::Bucket'))[0];
  const groups = ['Keys', 'Watch', 'Notify'];
  const ruleLogicals = groups.flatMap((g) => [logical('AWS::Events::Rule', new RegExp(`^KeyWatch${g}(?!B)`)), logical('AWS::Events::Rule', new RegExp(`^KeyWatch${g}B`))]);
  const ruleNames = ['keys', 'watch', 'notify'].flatMap((g) => [`vettid-votes-staging-kw-${g}`, `vettid-votes-staging-kw-${g}-b`]);
  const heartbeatRule = logical('AWS::Events::Rule', /^KeyWatchHeartbeat(?!Tick)/);
  const heartbeatLogs = logical('AWS::Logs::LogGroup', /^KeyWatchHeartbeatLogs/);
  const siteLogical = logical('AWS::KMS::Key', /^SiteSigningKey/);
  const heartbeatRoleLogical = logical('AWS::IAM::Role', /^KeyWatchHeartbeatRole/);
  const tickLogical = logical('AWS::Events::Rule', /^KeyWatchHeartbeatTick/);
  const heartbeatFnLogical = logical('AWS::Lambda::Function', /^KeyWatchHeartbeatFunction/);
  const heartbeatFnLogs = logical('AWS::Logs::LogGroup', /^KeyWatchHeartbeatFunctionLogs/);
  const topicA = logical('AWS::SNS::Topic', /^KeyWatchTopic(?!B)/);
  const topicB = logical('AWS::SNS::Topic', /^KeyWatchTopicB/);
  const queue = logical('AWS::SQS::Queue', /^KeyUseDeadLetters/);
  const logGroup = logical('AWS::Logs::LogGroup', /^KeyUseLogs/);
  const roleArn = { 'Fn::GetAtt': [publishLogical, 'Arn'] };
  const rootArn = { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':iam::123456789012:root']] };
  const fromRules = { ArnEquals: { 'aws:SourceArn': ruleLogicals.map((r) => ({ 'Fn::GetAtt': [r, 'Arn'] })) } };
  const keyPolicy = (algorithm: string): any => ({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'Administer', Effect: 'Allow', Principal: { AWS: rootArn }, Resource: '*',
        Action: ['kms:Create*', 'kms:Describe*', 'kms:Enable*', 'kms:List*', 'kms:Put*', 'kms:Update*', 'kms:Revoke*',
          'kms:Disable*', 'kms:Get*', 'kms:Delete*', 'kms:TagResource', 'kms:UntagResource',
          'kms:ScheduleKeyDeletion', 'kms:CancelKeyDeletion', 'kms:Verify'] },
      { Sid: 'PublishRoleSigns', Effect: 'Allow', Principal: { AWS: roleArn }, Resource: '*', Action: 'kms:Sign',
        Condition: { StringEquals: { 'kms:SigningAlgorithm': algorithm } } },
      { Sid: 'PublishRoleReads', Effect: 'Allow', Principal: { AWS: roleArn }, Resource: '*', Action: ['kms:GetPublicKey', 'kms:DescribeKey', 'kms:ListResourceTags'] },
      { Sid: 'OnlyThePublishRoleSigns', Effect: 'Deny', Principal: { AWS: '*' }, Resource: '*', Action: 'kms:Sign',
        Condition: { ArnNotEquals: { 'aws:PrincipalArn': roleArn } } },
      { Sid: 'NoGrants', Effect: 'Deny', Principal: { AWS: '*' }, Resource: '*', Action: 'kms:CreateGrant' },
      { Sid: 'OnlyRootDeletes', Effect: 'Deny', Principal: { AWS: '*' }, Resource: '*', Action: 'kms:ScheduleKeyDeletion',
        Condition: { ArnNotEquals: { 'aws:PrincipalArn': rootArn } } },
    ],
  });

  test('two signing keys made in KMS, never deleted with the stack; the stack refuses deletion', () => {
    expect(Object.keys(keys)).toHaveLength(2);
    for (const spec of ['ECC_NIST_EDWARDS25519', 'ECC_NIST_P256']) {
      const k = byUse(spec);
      expect(k).toBeDefined();
      expect(k.Properties.KeyUsage).toBe('SIGN_VERIFY');
      expect(k.Properties.Origin ?? 'AWS_KMS').toBe('AWS_KMS'); // made inside KMS: no import, so no copy outside it
      expect(k.DeletionPolicy).toBe('Retain');
      expect(k.Properties.PendingWindowInDays).toBe(30);
    }
    t.hasResourceProperties('AWS::KMS::Alias', { AliasName: 'alias/vettid-votes-staging-site' });
    t.hasResourceProperties('AWS::KMS::Alias', { AliasName: 'alias/vettid-votes-staging-list-anchor' });
    expect(stack('staging', 'staging').terminationProtection).toBe(true);
  });

  test('the list anchor key names its Sigstore instance in a tag, which votesctl checks', () => {
    for (const sigstore of ['staging', 'production'] as const) {
      const tt = synth('staging', sigstore);
      const ks = Object.values(tt.findResources('AWS::KMS::Key')) as any[];
      const bySpec = (spec: string): any => ks.find((r) => r.Properties.KeySpec === spec);
      const anchor = bySpec('ECC_NIST_P256');
      const site = bySpec('ECC_NIST_EDWARDS25519');
      expect(anchor.Properties.Tags).toEqual(expect.arrayContaining([{ Key: 'vettid:sigstore', Value: sigstore }]));
      expect((site.Properties.Tags ?? []).some((tg: any) => tg.Key === 'vettid:sigstore')).toBe(false);
    }
  });

  test('each key policy, whole: only the publish role signs, with its algorithm; no grants; only the root deletes', () => {
    expect(byUse('ECC_NIST_EDWARDS25519').Properties.KeyPolicy).toEqual(keyPolicy('ED25519_SHA_512'));
    expect(byUse('ECC_NIST_P256').Properties.KeyPolicy).toEqual(keyPolicy('ECDSA_SHA_256'));
  });

  test('the publish role, whole: assumed only by the operator, for an hour; the service list, and reading the watch subscriptions', () => {
    const role = t.findResources('AWS::IAM::Role')[publishLogical] as any;
    expect(role.Properties.MaxSessionDuration).toBe(3600);
    expect(role.Properties.ManagedPolicyArns).toBeUndefined();
    expect(role.Properties.AssumeRolePolicyDocument).toEqual({ Version: '2012-10-17',
      Statement: [{ Action: 'sts:AssumeRole', Effect: 'Allow', Principal: { AWS: PUBLISHER } }] });
    const pols = Object.values(t.findResources('AWS::IAM::Policy')).filter((p: any) =>
      asList(p.Properties.Roles).some((r: any) => r.Ref === publishLogical)) as any[];
    expect(pols).toHaveLength(1);
    const obj = (k: string): any => ({ 'Fn::Join': ['', [{ 'Fn::GetAtt': [bucketLogical, 'Arn'] }, '/' + k]] });
    expect(pols[0].Properties.PolicyDocument).toEqual({ Version: '2012-10-17', Statement: [
      { Sid: 'ServiceList', Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject'],
        Resource: [obj('v1/services.json'), obj('v1/services.json.sig'), obj('v1/services/*')] },
      // Unconditioned, so that a missing copy is a 404 (all documents are public).
      { Sid: 'ServiceListList', Effect: 'Allow', Action: 's3:ListBucket', Resource: { 'Fn::GetAtt': [bucketLogical, 'Arn'] } },
      // On the topics: SNS authorizes both against the topic.
      { Sid: 'KeyWatchSubscriptions', Effect: 'Allow', Action: ['sns:ListSubscriptionsByTopic', 'sns:GetSubscriptionAttributes'],
        Resource: [{ Ref: topicA }, { Ref: topicB }] },
    ] });
  });

  test('the publisher must be a role ARN of this account; the alarm topic and the watch email are required', () => {
    expect(validRoleArn(PUBLISHER)).toBe(true);
    expect(validRoleArn('arn:aws:iam::123456789012:user/alice')).toBe(false);
    expect(validRoleArn('arn:aws:iam::123456789012:root')).toBe(false);
    // An Identity Center permission set's role only (GC #12713), with or without its region.
    expect(validRoleArn('arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_VettIDVotesPublisher_0123456789abcdef')).toBe(true);
    expect(validRoleArn('arn:aws:iam::123456789012:role/admin')).toBe(false);
    expect(validRoleArn('arn:aws:iam::123456789012:role/vettid-votes-staging-publish')).toBe(false);
    expect(validRoleArn('arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Operator_0123')).toBe(false);
    expect(validRoleArn('arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Operator_0123456789abcdef/x')).toBe(false);
    expect(() => stack('x', 'staging', { publisherPrincipalArn: 'arn:aws:iam::123456789012:role/admin' })).toThrow(/permission set/);
    expect(validRoleArn('arn:aws:iam::123456789012:role/AWSReservedSSO_Operator_0123456789abcdef')).toBe(false); // no aws-reserved path
    expect(validRoleArn('arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_*_0123456789abcdef')).toBe(false);
    // The this-account check can't be skipped by an account left to deploy time.
    expect(() => new VotesStack(new cdk.App(), 'X', { envName: 'x', hostName: 'v.example.org', hostedZoneId: 'Z1', zoneName: 'example.org',
      sigstore: 'staging', publisherPrincipalArn: PUBLISHER, alarmTopicArn: TOPIC, githubOidcProviderArn: PROVIDER, keyWatchEmail: EMAIL,
      lambdaCode: lambda.Code.fromAsset(path.join(__dirname, 'fake-api')), env: { region: 'us-east-1' } })).toThrow(/needs its account/);
    expect(() => stack('x', 'staging', { publisherPrincipalArn: '*' })).toThrow(/publisherPrincipalArn/);
    expect(() => stack('x', 'staging', { publisherPrincipalArn: 'arn:aws:iam::210987654321:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Operator_0123456789abcdef' })).toThrow(/this account/);
    expect(() => stack('x', 'staging', { alarmTopicArn: undefined, githubOidcProviderArn: undefined })).toThrow(/alarmTopicArn/);
    expect(() => stack('x', 'staging', { keyWatchEmail: '' })).toThrow(/keyWatchEmail/);
    expect(() => stack('x', 'staging', { keyWatchEmail: 'not an address' })).toThrow(/keyWatchEmail/);
  });

  // The six rules of the watch (not the heartbeat's two, tested on their own).
  const rules = (): any[] => (Object.values(t.findResources('AWS::Events::Rule')) as any[])
    .filter((r) => !r.Properties.Name.startsWith('vettid-votes-staging-kw-heartbeat'));
  const firsts = (): any[] => rules().filter((r) => !r.Properties.Name.endsWith('-b'));
  const alts = (): any[] => firsts().flatMap((r) => r.Properties.EventPattern.detail.$or);
  const alt = (src: string): any[] => alts().filter((x) => x.eventSource[0] === src);

  test('six rules, three pairs: each pair one pattern, every rule the same targets, each in the state that gets read-only events, retained', () => {
    const r = rules();
    expect(r.map((x) => x.Properties.Name).sort()).toEqual([...ruleNames].sort());
    for (const g of ['keys', 'watch', 'notify']) {
      const [x, y] = ['', '-b'].map((sfx) => r.find((q) => q.Properties.Name === `vettid-votes-staging-kw-${g}${sfx}`));
      expect(y.Properties.EventPattern).toEqual(x.Properties.EventPattern);
    }
    for (const x of r) {
      expect(x.Properties.Targets).toEqual(r[0].Properties.Targets);
      expect(x.Properties.State).toBe('ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS');
      expect(x.DeletionPolicy).toBe('Retain');
      expect(x.Properties.EventPattern['detail-type']).toEqual(['AWS API Call via CloudTrail']);
    }
    expect(alts()).toHaveLength(16); // 14, plus a metric filter into the watch's namespace and the heartbeat's function
  });

  // Each pattern, its ARNs resolved at realistic lengths, stays under
  // EventBridge's default quota (a longer one fails the deploy).
  test('each pattern fits EventBridge\'s quota once resolved', () => {
    let longest = 0;
    const lengths: [string, number][] = [];
    for (const envName of ['staging', 'prod', 'production']) {
      const tpl = Template.fromStack(stack(envName, 'staging', {
        alarmTopicArn: 'arn:aws:sns:us-east-1:123456789012:vettid-org-staging-vault-alerts-topic-0123456789' })).toJSON();
      const res = tpl.Resources;
      const resolve = (v: any): any => {
        if (Array.isArray(v)) return v.map(resolve);
        if (v && typeof v === 'object') {
          if ('Ref' in v) {
            if (v.Ref === 'AWS::Partition') return 'aws';
            const r = res[v.Ref];
            const p = r.Properties;
            switch (r.Type) {
              case 'AWS::SNS::Topic': return `arn:aws:sns:us-east-1:123456789012:${p.TopicName}`;
              case 'AWS::SQS::Queue': return `https://sqs.us-east-1.amazonaws.com/123456789012/${p.QueueName}`;
              case 'AWS::Logs::LogGroup': return p.LogGroupName;
              case 'AWS::IAM::Role': return p.RoleName;
            }
            throw new Error(`a Ref to ${r.Type}`);
          }
          // The longest key ARN form (a multi-Region key).
          if ('Fn::GetAtt' in v) return 'arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef0123456789abcdef';
          if ('Fn::Join' in v) return resolve(v['Fn::Join'][1]).join(v['Fn::Join'][0]);
          return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, resolve(x)]));
        }
        return v;
      };
      // The six and the heartbeat's (its tick has a schedule, no pattern).
      const rs = Object.values(res).filter((r: any) => r.Type === 'AWS::Events::Rule' && r.Properties.EventPattern) as any[];
      expect(rs).toHaveLength(7);
      for (const r of rs) {
        const n = JSON.stringify(resolve(r.Properties.EventPattern)).length;
        if (n > longest) longest = n;
        lengths.push([r.Properties.Name, n]);
      }
    }
    if (process.env.KEY_WATCH_PATTERN_REPORT) console.log(lengths.map(([name, n]) => `${name}: ${n}`).join('\n'));
    // With room to spare.
    expect(lengths.filter(([, n]) => n >= KEY_WATCH_PATTERN_MAX - 200)).toEqual([]);
    expect(longest).toBeGreaterThan(0);
    expect(KEY_WATCH_PATTERN_MAX).toBe(2048);
  });

  test('watched, exactly: the keys and their aliases, the publish role', () => {
    expect([...KEY_USE_EVENTS]).toEqual(['Sign', 'CreateGrant', 'PutKeyPolicy', 'ScheduleKeyDeletion', 'DisableKey',
      'CreateAlias', 'UpdateAlias', 'DeleteAlias', 'TagResource', 'UntagResource']);
    const kmsArn = (resource: string): any => ({ 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, `:kms:us-east-1:123456789012:${resource}`]] });
    expect(alt('kms.amazonaws.com')).toEqual([{ eventSource: ['kms.amazonaws.com'], eventName: [...KEY_USE_EVENTS], resources: { ARN: [
      { 'Fn::GetAtt': [logical('AWS::KMS::Key', /^SiteSigningKey/), 'Arn'] }, { 'Fn::GetAtt': [logical('AWS::KMS::Key', /^ListAnchorKey/), 'Arn'] },
      kmsArn('alias/vettid-votes-staging-site'), kmsArn('alias/vettid-votes-staging-list-anchor')] } }]);
    expect([...PUBLISH_ROLE_EVENTS]).toEqual(['UpdateAssumeRolePolicy', 'PutRolePolicy', 'DeleteRolePolicy', 'AttachRolePolicy',
      'DetachRolePolicy', 'PutRolePermissionsBoundary', 'DeleteRolePermissionsBoundary', 'UpdateRole', 'DeleteRole']);
    // The publish role and the key watch heartbeat's.
    expect(alt('iam.amazonaws.com')).toEqual([{ eventSource: ['iam.amazonaws.com'], eventName: [...PUBLISH_ROLE_EVENTS],
      requestParameters: { roleName: [{ Ref: publishLogical }, { Ref: heartbeatRoleLogical }] } }]);
  });

  test('watched: the heartbeat\'s function (code, configuration, permission, concurrency), by name or ARN, in the watch pair', () => {
    expect(WATCH_EVENTS.heartbeatFunction).toEqual(['UpdateFunctionCode', 'UpdateFunctionConfiguration', 'DeleteFunction', 'AddPermission',
      'RemovePermission', 'PutFunctionConcurrency', 'DeleteFunctionConcurrency']);
    const fn = 'vettid-votes-staging-key-watch-heartbeat';
    const lambdaAlt = [{ eventSource: ['lambda.amazonaws.com'],
      // Prefixes: CloudTrail's names carry an API version (UpdateFunctionCode20150331v2).
      eventName: [{ prefix: 'UpdateFunctionCode' }, { prefix: 'UpdateFunctionConfiguration' }, { prefix: 'DeleteFunction' }, { prefix: 'AddPermission' },
        { prefix: 'RemovePermission' }, { prefix: 'PutFunctionConcurrency' }, { prefix: 'DeleteFunctionConcurrency' }],
      // The name, the name with a qualifier, a full or partial ARN, unqualified or $LATEST.
      requestParameters: { functionName: [fn, { prefix: `${fn}:` }, { suffix: `:function:${fn}` }, { suffix: `:function:${fn}:$LATEST` }] } }];
    expect(alt('lambda.amazonaws.com')).toEqual(lambdaAlt);
    const watchPair = rules().find((r) => r.Properties.Name === 'vettid-votes-staging-kw-watch').Properties.EventPattern.detail.$or;
    expect(watchPair.filter((x: any) => x.eventSource[0] === 'lambda.amazonaws.com')).toEqual(lambdaAlt);
    // Nothing of EventBridge Scheduler remains.
    t.resourceCountIs('AWS::Scheduler::Schedule', 0);
    expect(alt('scheduler.amazonaws.com')).toEqual([]);
  });

  test('watched, exactly: the watch itself, the trail, the topics, the dead letters, mute rules and this stack', () => {
    expect(WATCH_EVENTS).toEqual({
      rules: ['DisableRule', 'DeleteRule', 'PutRule', 'RemoveTargets', 'PutTargets'],
      alarms: ['DisableAlarmActions', 'EnableAlarmActions', 'DeleteAlarms', 'PutMetricAlarm', 'SetAlarmState'],
      logGroup: ['DeleteLogGroup', 'PutRetentionPolicy', 'DeleteRetentionPolicy', 'DeleteMetricFilter', 'PutMetricFilter',
        'DeleteLogStream', 'AssociateKmsKey', 'DisassociateKmsKey'],
      logPolicies: ['PutResourcePolicy', 'DeleteResourcePolicy'],
      trails: ['StopLogging', 'StartLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'PutAdvancedEventSelectors'],
      topics: ['Subscribe', 'ConfirmSubscription', 'Unsubscribe', 'SetSubscriptionAttributes', 'SetTopicAttributes', 'DeleteTopic',
        'AddPermission', 'RemovePermission', 'PutDataProtectionPolicy'],
      queue: ['PurgeQueue', 'DeleteQueue', 'SetQueueAttributes', 'AddPermission', 'RemovePermission'],
      muteRules: ['PutAlarmMuteRule', 'DeleteAlarmMuteRule'],
      stack: ['UpdateStack', 'DeleteStack', 'CreateChangeSet', 'ExecuteChangeSet', 'SetStackPolicy',
        'UpdateTerminationProtection', 'ContinueUpdateRollback', 'CancelUpdateStack', 'RollbackStack'],
      stackRefactor: ['CreateStackRefactor', 'ExecuteStackRefactor'],
      buses: ['UpdateEventBus'],
      heartbeatFunction: ['UpdateFunctionCode', 'UpdateFunctionConfiguration', 'DeleteFunction', 'AddPermission', 'RemovePermission',
        'PutFunctionConcurrency', 'DeleteFunctionConcurrency'],
    });
    // The six rules and the heartbeat's two (its line and its tick), by
    // the prefix of their names, which no other rule of the stack has.
    const watched = [{ prefix: 'vettid-votes-staging-kw-' }];
    const allRules = (Object.values(t.findResources('AWS::Events::Rule')) as any[]).map((r) => r.Properties.Name).sort();
    expect(allRules).toEqual([...ruleNames, 'vettid-votes-staging-kw-heartbeat', 'vettid-votes-staging-kw-heartbeat-tick'].sort());
    expect(allRules.every((n) => n.startsWith('vettid-votes-staging-kw-'))).toBe(true);
    expect(alt('events.amazonaws.com')).toEqual([
      { eventSource: ['events.amazonaws.com'], eventName: [...WATCH_EVENTS.rules], requestParameters: { $or: [{ name: watched }, { rule: watched }] } },
      { eventSource: ['events.amazonaws.com'], eventName: ['UpdateEventBus'] }, // any bus
    ]);
    const alarms = ['vettid-votes-staging-key-use', 'vettid-votes-staging-key-use-feed', 'vettid-votes-staging-key-watch-heartbeat'];
    // Mute rules in the watch pair; the alarms in the notify pair (for the quota).
    expect(alt('monitoring.amazonaws.com')).toEqual([
      { eventSource: ['monitoring.amazonaws.com'], eventName: [...WATCH_EVENTS.muteRules] }, // any mute rule
      { eventSource: ['monitoring.amazonaws.com'], eventName: [...WATCH_EVENTS.alarms], requestParameters: { $or: [{ alarmNames: alarms }, { alarmName: alarms }] } },
    ]);
    const group = (name: string): any[] => rules().find((r) => r.Properties.Name === `vettid-votes-staging-kw-${name}`).Properties.EventPattern.detail.$or;
    expect(group('notify').filter((x) => x.eventSource[0] === 'monitoring.amazonaws.com')).toHaveLength(1);
    expect(group('watch').filter((x) => x.eventSource[0] === 'monitoring.amazonaws.com')).toHaveLength(1);
    expect(alt('logs.amazonaws.com')).toEqual([
      { eventSource: ['logs.amazonaws.com'], eventName: [...WATCH_EVENTS.logGroup],
        requestParameters: { logGroupName: [{ Ref: logGroup }, '/vettid/votes/staging/key-watch-heartbeat'] } },
      { eventSource: ['logs.amazonaws.com'], eventName: [...WATCH_EVENTS.logPolicies] }, // any name
      // A metric filter on any log group into the watch's namespace.
      { eventSource: ['logs.amazonaws.com'], eventName: ['PutMetricFilter'],
        requestParameters: { metricTransformations: { metricNamespace: ['VettID/VotesKeys/staging'] } } },
    ]);
    expect(alt('cloudtrail.amazonaws.com')).toEqual([{ eventSource: ['cloudtrail.amazonaws.com'], eventName: [...WATCH_EVENTS.trails] }]); // any trail
    const topics = [TOPIC, { Ref: topicA }, { Ref: topicB }];
    const sns = { eventSource: ['sns.amazonaws.com'], eventName: [...WATCH_EVENTS.topics] };
    expect(alt('sns.amazonaws.com')).toEqual([{ ...sns, requestParameters: { $or: [
      { topicArn: topics },
      { resourceArn: topics }, // PutDataProtectionPolicy
      { subscriptionArn: [{ prefix: `${TOPIC}:` },
        { prefix: { 'Fn::Join': ['', [{ Ref: topicA }, ':']] } }, { prefix: { 'Fn::Join': ['', [{ Ref: topicB }, ':']] } }] },
    ] } }]);
    expect(alt('sqs.amazonaws.com')).toEqual([{ eventSource: ['sqs.amazonaws.com'], eventName: [...WATCH_EVENTS.queue],
      requestParameters: { queueUrl: [{ Ref: queue }] } }]);
    const cfn = { eventSource: ['cloudformation.amazonaws.com'], eventName: [...WATCH_EVENTS.stack] };
    expect(alt('cloudformation.amazonaws.com')).toEqual([
      { ...cfn, requestParameters: { stackName: ['VotesSite-staging', { prefix: { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' },
        ':cloudformation:us-east-1:123456789012:stack/VotesSite-staging/']] } }] } },
      { eventSource: ['cloudformation.amazonaws.com'], eventName: [...WATCH_EVENTS.stackRefactor] }, // any refactor
      { eventSource: ['cloudformation.amazonaws.com'], eventName: ['ExecuteChangeSet'], requestParameters: { stackName: [{ exists: false }] } },
    ]);
  });

  test('every event goes to the log group and, directly, to both watch topics; failures to the dead letters; never the session name', () => {
    for (const r of rules()) {
      const tg = r.Properties.Targets;
      expect(tg.map((x: any) => x.Arn)).toEqual([
        { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':logs:us-east-1:123456789012:log-group:', { Ref: logGroup }]] },
        { Ref: topicA }, { Ref: topicB }]);
      for (const x of tg) {
        expect(x.DeadLetterConfig).toEqual({ Arn: { 'Fn::GetAtt': [queue, 'Arn'] } });
        expect(x.RetryPolicy).toEqual({ MaximumRetryAttempts: 185, MaximumEventAgeInSeconds: 86400 });
        const paths = Object.values(x.InputTransformer.InputPathsMap) as string[];
        expect(paths).toEqual(expect.arrayContaining(['$.detail.eventName', '$.detail.userIdentity.sessionContext.sessionIssuer.arn',
          '$.detail.userIdentity.type', '$.detail.userIdentity.accessKeyId', '$.detail.eventID',
          '$.detail.requestParameters.name', '$.detail.requestParameters.topicArn', '$.detail.requestParameters.subscriptionArn',
          '$.detail.requestParameters.alarmName', '$.detail.requestParameters.stackName', '$.detail.requestParameters.alarmNames',
          '$.detail.requestParameters.policyName', '$.detail.requestParameters.changeSetName', '$.detail.requestParameters.trailName']));
        for (const pth of paths) expect(pth).not.toMatch(/userIdentity\.(arn|principalId|userName)$|sessionName|email/i);
      }
      // The shape a log group target needs: {"timestamp": <time>, "message": "..."}.
      expect(tg[0].InputTransformer.InputTemplate).toMatch(/^\{"timestamp":<time>,"message":"[^"]*"\}$/);
    }
    t.hasResource('AWS::Logs::LogGroup', { DeletionPolicy: 'Retain', Properties: { LogGroupName: '/vettid/votes/staging/key-use' } });
    for (const topic of [topicA, topicB]) {
      expect((t.findResources('AWS::SNS::Topic')[topic] as any).DeletionPolicy).toBe('Retain');
      const subs = Object.values(t.findResources('AWS::SNS::Subscription')).filter((s: any) => s.Properties.TopicArn.Ref === topic) as any[];
      expect(subs).toHaveLength(1);
      expect(subs[0].Properties).toEqual({ Protocol: 'email', Endpoint: EMAIL, TopicArn: { Ref: topic } });
      expect(subs[0].DeletionPolicy).toBe('Retain');
    }
  });

  test('each watch policy, whole: only the six rules write the key-use log group and the topics, only the heartbeat\'s its log group, the seven the dead letters; CloudWatch of this account the topics', () => {
    const lp = Object.values(t.findResources('AWS::Logs::ResourcePolicy')) as any[];
    expect(lp).toHaveLength(1);
    const arns = ruleLogicals.flatMap((r, i) => (i === 0 ? [] : ['","']).concat([{ 'Fn::GetAtt': [r, 'Arn'] } as any]));
    expect(lp[0].Properties).toEqual({ PolicyName: 'vettid-votes-staging-key-use', PolicyDocument: { 'Fn::Join': ['', [
      '{"Statement":[{"Action":["logs:CreateLogStream","logs:PutLogEvents"],"Condition":{"ArnEquals":{"aws:SourceArn":["',
      ...arns,
      '"]}},"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Resource":"', { 'Fn::GetAtt': [logGroup, 'Arn'] },
      '"},{"Action":["logs:CreateLogStream","logs:PutLogEvents"],"Condition":{"ArnEquals":{"aws:SourceArn":["', { 'Fn::GetAtt': [heartbeatRule, 'Arn'] },
      '"]}},"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Resource":"', { 'Fn::GetAtt': [heartbeatLogs, 'Arn'] },
      '"}],"Version":"2012-10-17"}']] } });
    const qp = Object.values(t.findResources('AWS::SQS::QueuePolicy')) as any[];
    expect(qp).toHaveLength(1);
    const q = { 'Fn::GetAtt': [queue, 'Arn'] };
    const fromAll = { ArnEquals: { 'aws:SourceArn': [...ruleLogicals, heartbeatRule].map((r) => ({ 'Fn::GetAtt': [r, 'Arn'] })) } };
    expect(qp[0].Properties.PolicyDocument).toEqual({ Version: '2012-10-17', Statement: [
      { Action: 'sqs:*', Condition: { Bool: { 'aws:SecureTransport': 'false' } }, Effect: 'Deny', Principal: { AWS: '*' }, Resource: q },
      { Action: 'sqs:SendMessage', Condition: fromAll, Effect: 'Allow', Principal: { Service: 'events.amazonaws.com' }, Resource: q },
    ] });
    const tps = t.findResources('AWS::SNS::TopicPolicy');
    expect(Object.keys(tps)).toHaveLength(2);
    for (const topic of [topicA, topicB]) {
      const tp = Object.values(tps).find((p: any) => p.Properties.Topics[0].Ref === topic) as any;
      const r = { Ref: topic };
      expect(tp.Properties.PolicyDocument).toEqual({ Version: '2012-10-17', Statement: [
        { Action: 'sns:Publish', Condition: { Bool: { 'aws:SecureTransport': 'false' } }, Effect: 'Deny', Principal: '*', Resource: r, Sid: 'AllowPublishThroughSSLOnly' },
        { Action: 'sns:Publish', Condition: { StringEquals: { 'aws:SourceAccount': '123456789012' } }, Effect: 'Allow',
          Principal: { Service: 'cloudwatch.amazonaws.com' }, Resource: r, Sid: 'Alarms' },
        { Action: 'sns:Publish', Condition: fromRules, Effect: 'Allow', Principal: { Service: 'events.amazonaws.com' }, Resource: r, Sid: 'Rules' },
      ] });
    }
  });

  test('alarms, to every topic: any watched event (SampleCount, outside the monitor\'s namespace), and a failed delivery', () => {
    const actions = [TOPIC, { Ref: topicA }, { Ref: topicB }];
    const use = Object.values(t.findResources('AWS::CloudWatch::Alarm', { Properties: { AlarmName: 'vettid-votes-staging-key-use' } }))[0] as any;
    expect(use.Properties).toMatchObject({ Namespace: 'VettID/VotesKeys/staging', MetricName: 'KeyUse', Statistic: 'SampleCount',
      Threshold: 1, ComparisonOperator: 'GreaterThanOrEqualToThreshold', EvaluationPeriods: 1, Period: 60, TreatMissingData: 'notBreaching' });
    expect(use.Properties.AlarmActions).toEqual(actions);
    const feed = Object.values(t.findResources('AWS::CloudWatch::Alarm', { Properties: { AlarmName: 'vettid-votes-staging-key-use-feed' } }))[0] as any;
    expect(feed.Properties.AlarmActions).toEqual(actions);
    expect(JSON.stringify(feed.Properties.AlarmDescription)).toMatch(/then purge them/);
    const exprs = feed.Properties.Metrics.filter((m: any) => m.Expression).map((m: any) => m.Expression);
    expect(exprs).toEqual(['FILL(f0, 0) + FILL(f1, 0) + FILL(f2, 0) + FILL(f3, 0) + FILL(f4, 0) + FILL(f5, 0) + FILL(d, 0)']);
    const text = JSON.stringify(feed.Properties.Metrics);
    expect(text).toContain('FailedInvocations');
    expect(text).toContain('ApproximateNumberOfMessagesVisible');
    for (const n of ruleNames) expect(text).toContain(`"${n}"`);
    t.hasResourceProperties('AWS::Logs::MetricFilter', { MetricTransformations: [Match.objectLike({ MetricNamespace: 'VettID/VotesKeys/staging' })] });
    expect(heartbeatNamespace('staging').startsWith('VettID/VotesKeys')).toBe(false);
  });

  test('the key-use metric filter and alarm, whole (the heartbeat does not touch them)', () => {
    const filters = Object.values(t.findResources('AWS::Logs::MetricFilter')) as any[];
    expect(filters).toHaveLength(2);
    expect(filters.find((f) => f.Properties.FilterName === 'vettid-votes-staging-key-use').Properties).toEqual({
      FilterName: 'vettid-votes-staging-key-use', LogGroupName: { Ref: logGroup }, FilterPattern: '',
      MetricTransformations: [{ MetricNamespace: 'VettID/VotesKeys/staging', MetricName: 'KeyUse', MetricValue: '1' }],
    });
    const use = Object.values(t.findResources('AWS::CloudWatch::Alarm', { Properties: { AlarmName: 'vettid-votes-staging-key-use' } }))[0] as any;
    expect(use.Properties).toEqual({
      AlarmName: 'vettid-votes-staging-key-use',
      AlarmDescription: {
        'Fn::Join': ['', ['A votes site key of staging, its publish role or this watch was used or changed: see ', { Ref: logGroup },
          '. A publish raises it (two signatures, each logged twice: four lines); a publish that does not means the feed is broken: stop and check it.']],
      },
      Namespace: 'VettID/VotesKeys/staging', MetricName: 'KeyUse', Statistic: 'SampleCount', Period: 60,
      Threshold: 1, ComparisonOperator: 'GreaterThanOrEqualToThreshold', EvaluationPeriods: 1, TreatMissingData: 'notBreaching',
      AlarmActions: [TOPIC, { Ref: topicA }, { Ref: topicB }],
    });
  });

  test('the key watch\'s heartbeat: a small inline Node.js function describes the site key by its ARN, retained', () => {
    const f = t.findResources('AWS::Lambda::Function')[heartbeatFnLogical] as any;
    expect(f.DeletionPolicy).toBe('Retain');
    const p = f.Properties;
    expect(p.FunctionName).toBe('vettid-votes-staging-key-watch-heartbeat');
    expect(p.Runtime).toBe('nodejs22.x');
    expect(p.Handler).toBe('index.handler');
    expect(p.Timeout).toBe(10);
    expect(p.MemorySize).toBe(128);
    expect(p.Role).toEqual({ 'Fn::GetAtt': [heartbeatRoleLogical, 'Arn'] });
    expect(p.Environment).toEqual({ Variables: { SITE_KEY_ARN: { 'Fn::GetAtt': [siteLogical, 'Arn'] } } });
    expect(p.LoggingConfig).toEqual({ LogGroup: { Ref: heartbeatFnLogs } });
    // Inline, nothing bundled: the runtime's SDK, and a failed call throws.
    expect(p.Code.ZipFile).toContain('DescribeKeyCommand');
    expect(p.Code.ZipFile).toContain('process.env.SITE_KEY_ARN');
    expect(p.Code.S3Bucket).toBeUndefined();
    // No VPC, no reserved concurrency.
    expect(p.VpcConfig).toBeUndefined();
    expect(p.ReservedConcurrentExecutions).toBeUndefined();
    const lg = t.findResources('AWS::Logs::LogGroup')[heartbeatFnLogs] as any;
    expect(lg.DeletionPolicy).toBe('Retain');
    expect(lg.Properties).toEqual({ LogGroupName: '/aws/lambda/vettid-votes-staging-key-watch-heartbeat', RetentionInDays: 30 });
  });

  test('its tick: a rule on the default bus, hourly, to the function, retained; only that rule may invoke it', () => {
    const r = t.findResources('AWS::Events::Rule')[tickLogical] as any;
    expect(r.DeletionPolicy).toBe('Retain');
    expect(r.Properties.Name).toBe('vettid-votes-staging-kw-heartbeat-tick');
    expect(r.Properties.ScheduleExpression).toBe('rate(1 hour)');
    expect(r.Properties.EventBusName).toBeUndefined(); // the default bus
    expect(r.Properties.EventPattern).toBeUndefined();
    expect(r.Properties.Targets).toEqual([{ Id: r.Properties.Targets[0].Id, Arn: { 'Fn::GetAtt': [heartbeatFnLogical, 'Arn'] } }]);
    const perms = (Object.values(t.findResources('AWS::Lambda::Permission')) as any[])
      .filter((x) => JSON.stringify(x.Properties.FunctionName).includes(heartbeatFnLogical));
    expect(perms.map((x) => x.Properties)).toEqual([{
      Action: 'lambda:InvokeFunction', FunctionName: { 'Fn::GetAtt': [heartbeatFnLogical, 'Arn'] },
      Principal: 'events.amazonaws.com', SourceArn: { 'Fn::GetAtt': [tickLogical, 'Arn'] },
    }]);
  });

  test('its role: assumed only by Lambda, no path; only DescribeKey on the site key and its own log group', () => {
    const role = t.findResources('AWS::IAM::Role')[heartbeatRoleLogical] as any;
    expect(role.DeletionPolicy).toBe('Retain');
    expect(role.Properties.RoleName).toBe('vettid-votes-staging-key-watch-heartbeat');
    expect(role.Properties.Path).toBeUndefined();
    expect(role.Properties.ManagedPolicyArns).toBeUndefined();
    expect(role.Properties.PermissionsBoundary).toBeUndefined();
    expect(role.Properties.AssumeRolePolicyDocument).toEqual({ Version: '2012-10-17', Statement: [{
      Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { Service: 'lambda.amazonaws.com' },
    }] });
    expect(role.Properties.Policies).toEqual([{ PolicyName: 'KeyWatchHeartbeat', PolicyDocument: { Version: '2012-10-17', Statement: [
      { Sid: 'DescribeSiteKey', Effect: 'Allow', Action: 'kms:DescribeKey', Resource: { 'Fn::GetAtt': [siteLogical, 'Arn'] } },
      { Sid: 'Logs', Effect: 'Allow', Action: ['logs:CreateLogStream', 'logs:PutLogEvents'], Resource: { 'Fn::GetAtt': [heartbeatFnLogs, 'Arn'] } },
    ] } }]);
    // No other policy names it.
    const others = (Object.values(t.findResources('AWS::IAM::Policy')) as any[])
      .filter((p) => JSON.stringify(p.Properties.Roles).includes(heartbeatRoleLogical));
    expect(others).toEqual([]);
  });

  test('its rule: that role\'s DescribeKey of the site key, in the read-only state, retained', () => {
    const r = t.findResources('AWS::Events::Rule')[heartbeatRule] as any;
    expect(r.DeletionPolicy).toBe('Retain');
    expect(r.Properties.Name).toBe('vettid-votes-staging-kw-heartbeat');
    expect(r.Properties.State).toBe('ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS');
    expect(r.Properties.EventPattern).toEqual({
      'detail-type': ['AWS API Call via CloudTrail'],
      detail: {
        eventSource: ['kms.amazonaws.com'], eventName: ['DescribeKey'], resources: { ARN: [{ 'Fn::GetAtt': [siteLogical, 'Arn'] }] },
        userIdentity: { sessionContext: { sessionIssuer: { arn: [{ 'Fn::GetAtt': [heartbeatRoleLogical, 'Arn'] }] } } },
        errorCode: [{ exists: false }],
      },
    });
  });

  test('its one target: its own log group, the raw event, the same dead letters and retries; no topic', () => {
    const r = t.findResources('AWS::Events::Rule')[heartbeatRule] as any;
    expect(r.Properties.Targets).toEqual([{
      Id: r.Properties.Targets[0].Id,
      Arn: { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':logs:us-east-1:123456789012:log-group:', { Ref: heartbeatLogs }]] },
      DeadLetterConfig: { Arn: { 'Fn::GetAtt': [queue, 'Arn'] } },
      RetryPolicy: { MaximumRetryAttempts: 185, MaximumEventAgeInSeconds: 86400 },
    }]);
    const lg = t.findResources('AWS::Logs::LogGroup')[heartbeatLogs] as any;
    expect(lg.DeletionPolicy).toBe('Retain');
    expect(lg.Properties).toEqual({ LogGroupName: '/vettid/votes/staging/key-watch-heartbeat', RetentionInDays: 30 });
  });

  test('its alarm: three hours without a line (SampleCount), missing data breaching, to every topic; its recovery to the alarm topic', () => {
    const filters = Object.values(t.findResources('AWS::Logs::MetricFilter')) as any[];
    expect(filters.find((f) => f.Properties.FilterName === 'vettid-votes-staging-key-watch-heartbeat').Properties).toEqual({
      FilterName: 'vettid-votes-staging-key-watch-heartbeat', LogGroupName: { Ref: heartbeatLogs }, FilterPattern: '',
      MetricTransformations: [{ MetricNamespace: 'VettID/VotesKeys/staging', MetricName: 'KeyWatchHeartbeat', MetricValue: '1' }],
    });
    const a = Object.values(t.findResources('AWS::CloudWatch::Alarm', { Properties: { AlarmName: 'vettid-votes-staging-key-watch-heartbeat' } })) as any[];
    expect(a).toHaveLength(1);
    expect(a[0].Properties).toEqual({
      AlarmName: 'vettid-votes-staging-key-watch-heartbeat',
      AlarmDescription: { 'Fn::Join': ['', ['No hourly DescribeKey of the votes site key of staging reached ', { Ref: heartbeatLogs },
        ' in 3 hours: the key watch\'s feed may be broken (the trail, the default bus, the rule, the log policy), ' +
        'or the rule vettid-votes-staging-kw-heartbeat-tick or the function vettid-votes-staging-key-watch-heartbeat did not run or failed (README "The heartbeat").']] },
      Namespace: 'VettID/VotesKeys/staging', MetricName: 'KeyWatchHeartbeat', Statistic: 'SampleCount', Period: 3600,
      Threshold: 1, ComparisonOperator: 'LessThanThreshold', EvaluationPeriods: 3, DatapointsToAlarm: 3, TreatMissingData: 'breaching',
      AlarmActions: [TOPIC, { Ref: topicA }, { Ref: topicB }],
      OKActions: [TOPIC],
    });
    expect(KEY_WATCH_HEARTBEAT_HOURS).toBe(3);
    expect(HEARTBEAT.hours).toBe(12);
  });

  test('outputs', () => {
    for (const o of ['SiteSigningKeyArn', 'ListAnchorKeyArn', 'PublishRoleArn', 'KeyWatchTopicArn', 'KeyWatchTopicBArn']) t.hasOutput(o, {});
  });
});
