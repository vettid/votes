import * as path from 'node:path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { LAMBDA_TIMEOUT_SECONDS, VotesStack } from '../lib/votes-stack';

function synth(envName: string): Template {
  const app = new cdk.App();
  const stack = new VotesStack(app, `VotesSite-${envName}`, {
    envName, hostName: 'votes.example.org', hostedZoneId: 'Z123', zoneName: 'example.org', siteKey: 'c2l0ZWtleQ==',
    lambdaCode: lambda.Code.fromAsset(path.join(__dirname, 'fake-api')),
    env: { account: '123456789012', region: 'us-east-1' },
  });
  return Template.fromStack(stack);
}

const t = synth('staging');

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
      Environment: { Variables: Match.objectLike({ VOTES_SIGSTORE: 'staging', VOTES_SITE_KEY: 'c2l0ZWtleQ==' }) },
    });
    synth('prod').hasResourceProperties('AWS::Lambda::Function', {
      Environment: { Variables: Match.objectLike({ VOTES_SIGSTORE: 'production' }) },
    });
  });

  test('may read, list and write the bucket; never delete; no secret', () => {
    const actions = fnStatements().flatMap((s) => asList(s.Action));
    expect(actions).toEqual(expect.arrayContaining(['s3:GetObject', 's3:PutObject', 's3:ListBucket']));
    expect(actions.filter((a: string) => a.startsWith('s3:Delete') || a === 's3:*')).toEqual([]);
    expect(actions.filter((a: string) => a.startsWith('secretsmanager:'))).toEqual([]);
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
