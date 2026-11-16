import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { API_RATE_LIMIT, API_RATE_WINDOW_SECONDS, HEARTBEAT, heartbeatNamespace, KEY_USE_EVENTS, LAMBDA_TIMEOUT_SECONDS, MONITOR_OIDC, PUBLISH_ROLE_EVENTS, VotesStack, validRoleArn, validSiteKey, WATCH_EVENTS } from '../lib/votes-stack';

// A fixed public test value, not a real key: 32 bytes of 0x07.
const SITE_KEY = Buffer.alloc(32, 7).toString('base64');

// The operator's role, as an IAM Identity Center role ARN looks (a test value).
const PUBLISHER = 'arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Operator_0123456789abcdef';

type Extra = { siteKey?: string; region?: string; servicesRepair?: boolean; alarmTopicArn?: string; githubOidcProviderArn?: string; publisherPrincipalArn?: string };
function stack(envName: string, sigstore: 'staging' | 'production', extra: Extra = {}): VotesStack {
  const app = new cdk.App();
  return new VotesStack(app, `VotesSite-${envName}`, {
    envName, hostName: 'votes.example.org', hostedZoneId: 'Z123', zoneName: 'example.org', sigstore,
    siteKey: 'siteKey' in extra ? extra.siteKey : SITE_KEY,
    servicesRepair: extra.servicesRepair,
    alarmTopicArn: extra.alarmTopicArn,
    githubOidcProviderArn: extra.githubOidcProviderArn,
    publisherPrincipalArn: extra.publisherPrincipalArn ?? PUBLISHER,
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
    // The function's, and the publish role (site keys, below); no other,
    // and none with a managed policy (no helper Lambda either).
    const roles = Object.values(t.findResources('AWS::IAM::Role')) as any[];
    expect(roles.map((r) => r.Properties.RoleName).sort()).toEqual(['vettid-votes-staging-api', 'vettid-votes-staging-publish']);
    for (const r of roles) expect(r.Properties.ManagedPolicyArns).toBeUndefined();
    t.resourceCountIs('AWS::Lambda::Function', 1);
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
    expect((Object.values(t.findResources('AWS::IAM::Role')) as any[]).map((r) => r.Properties.RoleName).sort())
      .toEqual(['vettid-votes-staging-api', 'vettid-votes-staging-publish']);
    t.resourceCountIs('AWS::CloudWatch::Alarm', 0);
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
  });

  test('the heartbeat alarm: three hours without a successful run, missing data breaching, to the topic', () => {
    m.resourceCountIs('AWS::CloudWatch::Alarm', 3); // and the key-use and feed alarms (site keys, below)
    m.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmName: 'vettid-votes-staging-monitor-heartbeat',
      Namespace: heartbeatNamespace('staging'), MetricName: 'MonitorHeartbeat', Dimensions: [{ Name: 'env', Value: 'staging' }],
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

describe('site keys (VOTE-SITE-KEY-COMPROMISE §6)', () => {
  const TOPIC = 'arn:aws:sns:us-east-1:123456789012:vettid-alarms';
  const PROVIDER = 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com';
  const keys = t.findResources('AWS::KMS::Key');
  const byUse = (spec: string): any => Object.values(keys).find((k: any) => k.Properties.KeySpec === spec) as any;
  const publishLogical = Object.keys(t.findResources('AWS::IAM::Role', { Properties: { RoleName: 'vettid-votes-staging-publish' } }))[0];

  test('two signing keys made in KMS, never deleted with the stack', () => {
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
  });

  test('only the publish role signs; no grants; only the root deletes', () => {
    for (const spec of ['ECC_NIST_EDWARDS25519', 'ECC_NIST_P256']) {
      const st: any[] = byUse(spec).Properties.KeyPolicy.Statement;
      const allowSign = st.filter((x) => x.Effect === 'Allow' && asList(x.Action).some((a: string) => a === 'kms:Sign' || a === 'kms:*' || a === 'kms:Sign*'));
      expect(allowSign).toHaveLength(1);
      expect(allowSign[0].Principal.AWS).toEqual({ 'Fn::GetAtt': [publishLogical, 'Arn'] });
      const admin = st.find((x) => x.Sid === 'Administer');
      for (const a of asList(admin.Action)) {
        expect(a).not.toMatch(/^kms:(\*|Sign)/);
      }
      expect(st.find((x) => x.Sid === 'OnlyThePublishRoleSigns')).toMatchObject({ Effect: 'Deny', Principal: { AWS: '*' }, Action: 'kms:Sign',
        Condition: { ArnNotEquals: { 'aws:PrincipalArn': { 'Fn::GetAtt': [publishLogical, 'Arn'] } } } });
      expect(st.find((x) => x.Sid === 'NoGrants')).toMatchObject({ Effect: 'Deny', Principal: { AWS: '*' }, Action: 'kms:CreateGrant' });
      const del = st.find((x) => x.Sid === 'OnlyRootDeletes');
      expect(del).toMatchObject({ Effect: 'Deny', Principal: { AWS: '*' }, Action: 'kms:ScheduleKeyDeletion' });
      expect(JSON.stringify(del.Condition.ArnNotEquals['aws:PrincipalArn'])).toContain(':root');
    }
  });

  test('the publish role: assumed only by the operator, for an hour; the service list and nothing else', () => {
    const role = t.findResources('AWS::IAM::Role')[publishLogical] as any;
    expect(role.Properties.MaxSessionDuration).toBe(3600);
    expect(role.Properties.AssumeRolePolicyDocument.Statement).toEqual([
      { Action: 'sts:AssumeRole', Effect: 'Allow', Principal: { AWS: PUBLISHER } },
    ]);
    const pol = Object.values(t.findResources('AWS::IAM::Policy')).find((p: any) =>
      asList(p.Properties.Roles).some((r: any) => r.Ref === publishLogical)) as any;
    const st: any[] = pol.Properties.PolicyDocument.Statement;
    expect(st.map((x) => x.Sid).sort()).toEqual(['ServiceList', 'ServiceListList']);
    expect(JSON.stringify(st.find((x) => x.Sid === 'ServiceList').Resource)).toContain('/v1/services*');
    // Unconditioned, so that a missing copy is a 404 (all documents are public).
    expect(st.find((x) => x.Sid === 'ServiceListList')).toMatchObject({ Action: 's3:ListBucket', Resource: { 'Fn::GetAtt': [expect.stringMatching(/^Bucket/), 'Arn'] } });
    expect(st.find((x) => x.Sid === 'ServiceListList').Condition).toBeUndefined();
    // No KMS in the role's own policy: the key policies are what let it sign.
    expect(JSON.stringify(st)).not.toContain('kms:');
  });

  test('the publisher must be a role ARN', () => {
    expect(validRoleArn(PUBLISHER)).toBe(true);
    expect(validRoleArn('arn:aws:iam::123456789012:user/alice')).toBe(false);
    expect(validRoleArn('arn:aws:iam::123456789012:root')).toBe(false);
    expect(() => stack('x', 'staging', { publisherPrincipalArn: '*' })).toThrow(/publisherPrincipalArn/);
  });

  const rules = (): any[] => Object.values(t.findResources('AWS::Events::Rule')) as any[];
  const alts = (): any[] => rules()[0].Properties.EventPattern.detail.$or;
  const alt = (src: string): any[] => alts().filter((x) => x.eventSource[0] === src);

  test('two rules with one pattern, each in the state that gets read-only events', () => {
    const r = rules();
    expect(r.map((x) => x.Properties.Name).sort()).toEqual(['vettid-votes-staging-key-use', 'vettid-votes-staging-key-use-b']);
    expect(r[1].Properties.EventPattern).toEqual(r[0].Properties.EventPattern);
    for (const x of r) expect(x.Properties.State).toBe('ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS');
    expect(r[0].Properties.EventPattern['detail-type']).toEqual(['AWS API Call via CloudTrail']);
  });

  test('watched: the keys, the publish role, and the watch itself', () => {
    const k = alt('kms.amazonaws.com');
    expect(k).toHaveLength(1);
    expect(k[0].eventName).toEqual([...KEY_USE_EVENTS]);
    expect(k[0].eventName).toEqual(expect.arrayContaining(['Sign', 'CreateGrant', 'PutKeyPolicy', 'UpdateAlias']));
    expect(k[0].resources.ARN).toHaveLength(2);
    const i = alt('iam.amazonaws.com');
    expect(i).toHaveLength(1);
    expect(i[0].eventName).toEqual([...PUBLISH_ROLE_EVENTS]);
    expect(i[0].eventName).toEqual(expect.arrayContaining(['UpdateAssumeRolePolicy', 'PutRolePolicy', 'AttachRolePolicy']));
    expect(i[0].requestParameters.roleName).toEqual([{ Ref: publishLogical }]);
    const ev = JSON.stringify(alt('events.amazonaws.com'));
    expect(ev).toContain('DisableRule');
    expect(ev).toContain('vettid-votes-staging-key-use-b');
    const mon = JSON.stringify(alt('monitoring.amazonaws.com'));
    for (const w of ['DisableAlarmActions', 'DeleteAlarms', 'vettid-votes-staging-key-use-feed']) expect(mon).toContain(w);
    const lg = JSON.stringify(alt('logs.amazonaws.com'));
    for (const w of ['DeleteMetricFilter', 'DeleteResourcePolicy', 'DeleteLogGroup', 'vettid-votes-staging-key-use']) expect(lg).toContain(w);
    for (const src of Object.keys(WATCH_EVENTS)) expect(alt(src).length).toBeGreaterThan(0);
  });

  test('every use is logged, without the session name; failed deliveries go to the dead letters', () => {
    for (const r of rules()) {
      expect(r.Properties.Targets).toHaveLength(1);
      const tg = r.Properties.Targets[0];
      expect(JSON.stringify(tg.Arn)).toContain(':log-group:');
      expect(tg.DeadLetterConfig.Arn).toEqual({ 'Fn::GetAtt': [expect.stringMatching(/^KeyUseDeadLetters/), 'Arn'] });
      const paths = Object.values(tg.InputTransformer.InputPathsMap) as string[];
      expect(paths).toEqual(expect.arrayContaining(['$.time', '$.detail.eventName', '$.detail.userIdentity.sessionContext.sessionIssuer.arn',
        '$.detail.userIdentity.type', '$.detail.userIdentity.accessKeyId', '$.detail.eventID']));
      for (const pth of paths) {
        expect(pth).not.toMatch(/userIdentity\.(arn|principalId|userName)$|sessionName|email/);
      }
      // The shape a log group target needs: {"timestamp": <time>, "message": "..."}.
      expect(tg.InputTransformer.InputTemplate).toMatch(/^\{"timestamp":<time>,"message":"[^"]*"\}$/);
    }
    t.hasResource('AWS::Logs::LogGroup', { DeletionPolicy: 'Retain', Properties: { LogGroupName: '/vettid/votes/staging/key-use' } });
    // Without a topic, no alarm.
    expect(Object.keys(t.findResources('AWS::CloudWatch::Alarm'))).toHaveLength(0);
  });

  test('only the two rules may write the log group and the dead letters', () => {
    const lp = Object.values(t.findResources('AWS::Logs::ResourcePolicy'))[0] as any;
    const doc = JSON.parse(lp.Properties.PolicyDocument['Fn::Join'] ? JSON.stringify(lp.Properties.PolicyDocument) : lp.Properties.PolicyDocument);
    const text = JSON.stringify(doc);
    expect(text).toContain('events.amazonaws.com');
    expect(text).not.toContain('delivery.logs.amazonaws.com');
    expect(text).toContain('aws:SourceArn');
    const qp = Object.values(t.findResources('AWS::SQS::QueuePolicy'))[0] as any;
    const send = qp.Properties.PolicyDocument.Statement.find((x: any) => x.Action === 'sqs:SendMessage');
    expect(send.Principal).toEqual({ Service: 'events.amazonaws.com' });
    expect(send.Condition.ArnEquals['aws:SourceArn']).toHaveLength(2);
  });

  test('with the alert topic: any use raises the key-use alarm (SampleCount, outside the monitor\'s namespace), and a failed delivery the feed alarm', () => {
    const a = Template.fromStack(stack('staging', 'staging', { alarmTopicArn: TOPIC, githubOidcProviderArn: PROVIDER }));
    a.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmName: 'vettid-votes-staging-key-use', Namespace: 'VettID/VotesKeys/staging', MetricName: 'KeyUse', Statistic: 'SampleCount',
      Threshold: 1, ComparisonOperator: 'GreaterThanOrEqualToThreshold', EvaluationPeriods: 1, Period: 60,
      AlarmActions: [TOPIC], TreatMissingData: 'notBreaching',
    });
    const feed = Object.values(a.findResources('AWS::CloudWatch::Alarm', { Properties: { AlarmName: 'vettid-votes-staging-key-use-feed' } }))[0] as any;
    expect(feed.Properties.AlarmActions).toEqual([TOPIC]);
    const text = JSON.stringify(feed.Properties.Metrics);
    expect(text).toContain('FailedInvocations');
    expect(text).toContain('ApproximateNumberOfMessagesVisible');
    expect(text).toContain('vettid-votes-staging-key-use-b');
    a.hasResourceProperties('AWS::Logs::MetricFilter', { MetricTransformations: [Match.objectLike({ MetricNamespace: 'VettID/VotesKeys/staging' })] });
    expect(heartbeatNamespace('staging').startsWith('VettID/VotesKeys')).toBe(false);
  });

  test('outputs', () => {
    t.hasOutput('SiteSigningKeyArn', {});
    t.hasOutput('ListAnchorKeyArn', {});
    t.hasOutput('PublishRoleArn', {});
  });
});
