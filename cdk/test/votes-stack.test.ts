import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { LAMBDA_TIMEOUT_SECONDS, VotesStack, validSiteKey } from '../lib/votes-stack';

// A fixed public test value, not a real key: 32 bytes of 0x07.
const SITE_KEY = Buffer.alloc(32, 7).toString('base64');

function stack(envName: string, sigstore: 'staging' | 'production', extra: { siteKey?: string; region?: string } = {}): VotesStack {
  const app = new cdk.App();
  return new VotesStack(app, `VotesSite-${envName}`, {
    envName, hostName: 'votes.example.org', hostedZoneId: 'Z123', zoneName: 'example.org', sigstore,
    siteKey: 'siteKey' in extra ? extra.siteKey : SITE_KEY,
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

  test('published documents: written only with If-None-Match, never deleted, for every principal', () => {
    const p = Object.values(t.findResources('AWS::S3::BucketPolicy'))[0] as any;
    const st: any[] = p.Properties.PolicyDocument.Statement;
    const once = st.find((x) => x.Sid === 'PublishedWriteOnce');
    expect(once).toMatchObject({ Effect: 'Deny', Principal: { AWS: '*' }, Action: 's3:PutObject',
      Condition: { Null: { 's3:if-none-match': 'true' } } });
    expect(JSON.stringify(once.Resource)).toContain('/v1/p/*');
    const keep = st.find((x) => x.Sid === 'PublishedNeverDeleted');
    expect(keep).toMatchObject({ Effect: 'Deny', Principal: { AWS: '*' } });
    expect(keep.Action).toEqual(expect.arrayContaining(['s3:DeleteObject', 's3:DeleteObjectVersion']));
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
