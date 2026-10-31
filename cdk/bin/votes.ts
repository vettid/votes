#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { VotesStack } from '../lib/votes-stack';

// Parameters come from context (cdk.json, ~/.cdk.json or -c key=value),
// all required: envName, hostName, hostedZoneId, zoneName, sigstore
// (staging or production), and siteKey (the site's public key from
// `votesctl site-key`) on every deploy but the first, which passes
// firstDeploy=true instead. See README "Deployment".
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

const envName = required('envName');
const sigstore = required('sigstore');
if (sigstore !== 'staging' && sigstore !== 'production') throw new Error('context "sigstore" is staging or production');
const siteKey = ctx('siteKey');
if (siteKey === undefined && ctx('firstDeploy') !== 'true') {
  throw new Error('context "siteKey" is required (votesctl site-key); only the first deploy may pass firstDeploy=true instead');
}
// Recovery only (README "Clearing a stray version copy").
const repair = ctx('servicesRepair');
if (repair !== undefined && repair !== 'true') throw new Error('context "servicesRepair" is true or absent');
// Confirmed in the environment too, so a value left in cdk.json or
// ~/.cdk.json can't keep deletes open deploy after deploy.
if (repair === 'true' && process.env.VOTES_SERVICES_REPAIR !== 'confirm') {
  throw new Error('servicesRepair=true needs VOTES_SERVICES_REPAIR=confirm in the environment (README "Clearing a stray version copy")');
}
const stack = new VotesStack(app, `VotesSite-${envName}`, {
  envName,
  hostName: required('hostName'),
  hostedZoneId: required('hostedZoneId'),
  zoneName: required('zoneName'),
  sigstore,
  siteKey,
  servicesRepair: repair === 'true',
  // Pinned: CloudFront's certificate must be in us-east-1.
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'us-east-1' },
  description: `votes.vettid.org (${envName})`,
});
cdk.Tags.of(stack).add('project', 'vettid');
cdk.Tags.of(stack).add('component', 'votes');
cdk.Tags.of(stack).add('env', envName);
