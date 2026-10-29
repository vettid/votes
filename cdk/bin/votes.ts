#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { VotesStack } from '../lib/votes-stack';

// Parameters come from context (cdk.json, ~/.cdk.json or -c key=value):
//   envName (default prod), hostName, hostedZoneId, zoneName (required),
//   siteKey (the site's public key from `votesctl site-key`, once the
//   first deploy made its secret). See README "Deployment".
const app = new cdk.App();
const ctx = (key: string): string | undefined => {
  const v = app.node.tryGetContext(key);
  return v === undefined || v === '' ? undefined : String(v);
};
const required = (key: string): string => {
  const v = ctx(key);
  if (v === undefined) throw new Error(`context "${key}" is required (cdk synth -c ${key}=...)`);
  return v;
};

const envName = ctx('envName') ?? 'prod';
const stack = new VotesStack(app, `VotesSite-${envName}`, {
  envName,
  hostName: required('hostName'),
  hostedZoneId: required('hostedZoneId'),
  zoneName: required('zoneName'),
  siteKey: ctx('siteKey'),
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1' },
  description: `votes.vettid.org (${envName})`,
});
cdk.Tags.of(stack).add('project', 'vettid');
cdk.Tags.of(stack).add('component', 'votes');
cdk.Tags.of(stack).add('env', envName);
