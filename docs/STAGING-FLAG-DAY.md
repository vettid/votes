# Staging: the votes site starts fresh under its KMS keys

**Status:** draft runbook, GC #12656 (plan #12646, step 5). Rule 3 (GC
#r58: no backward compatibility before production users) replaces the
planned migration: the staging site's service list starts again at
version 1, signed with the KMS site key and logged in Rekor from the
start, and the test connections are re-invited. The owner runs every
deploy, deletion and publish, each with its own go. The vettid-vault
staging release is the other session's, with its own go. Production has
its KMS keys from its first deploy and needs none of this.

**State when this was written (read-only checks, 2026-11-17):**
- `VotesSite-staging` was last updated 2026-11-03. None of votes #33–#36
  is deployed: no KMS keys or aliases, no `PublishRoleArn` or
  `ListAnchorKeyArn` outputs, no termination protection, no
  `MonitorRoleArn`.
- `vettid-votes-staging-api` runs with `VOTES_SIGSTORE=staging`.
- The site serves service list version 1, under the secret's key, with
  no bundle.
- The trail is an organization trail, homed in `us-east-1`, logging all
  management events.
- The secret `vettid-votes-staging/site-key` exists and isn't scheduled
  for deletion.

## 0. Before the first go

Owner prerequisites, once (README "Deployment"):
- [ ] The IAM Identity Center permission set `VettIDVotesPublisher`
  (GC #12713). Its only permission is an inline policy allowing
  `sts:AssumeRole` on `arn:aws:iam::<staging account>:role/vettid-votes-staging-publish`.
  Assign it in the staging account to the owner alone. Its role's ARN
  (`aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/`)
  is `publisherPrincipalArn`.
- [ ] A GitHub OIDC provider in the staging account (there is none):
  `aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com`.
  Its ARN is `githubOidcProviderArn`.
- [ ] `keyWatchEmail` in `~/.cdk.json` on the deploying machine, never in
  the tracked `cdk.json` or shell history.
- [ ] `alarmTopicArn`: the existing topic `vettid-org-staging-vault-alerts`.

## 1. Deploy, with deletes allowed under `v1/services/` (go 1)

From `cdk/` after `npm ci`, with `VOTES_SERVICES_REPAIR=confirm` in the
environment:

`npx cdk deploy -c envName=staging -c hostName=votes.staging.vettid.org -c hostedZoneId=<id> -c zoneName=vettid.org -c sigstore=staging -c siteKey=<the secret's key, for now> -c publisherPrincipalArn=<step 0> -c alarmTopicArn=<step 0> -c githubOidcProviderArn=<step 0> -c servicesRepair=true`
(`keyWatchEmail` from `~/.cdk.json`).

The deploy is watched: the stack update and the list anchor key's
`TagResource` are emailed on both watch topics. That is the deploy, not
an incident.

## 2. After the deploy (README "After the first deploy")

- [ ] Both watch subscriptions confirmed from their emails' tokens with
  `--authenticate-on-unsubscribe true` (owner); then
  `ConfirmationWasAuthenticated` is `true` on each.
- [ ] A test `UpdateEventBus` on the default bus (its description, put
  back as it was) is emailed (owner).
- [ ] A call only a nested match catches is emailed, e.g. a `PutRule`
  rewriting a `-b` rule's description as it was (owner).
- [ ] The log group's lines arrive (the `aws:SourceArn` condition lets
  the rules write).
- [ ] `aws kms list-resource-tags` on `ListAnchorKeyArn`, as the publish
  role: `vettid:sigstore` = `staging`.
- [ ] Repository variables `VOTES_STAGING_MONITOR_ROLE_ARN` (output
  `MonitorRoleArn`) and `VOTES_STAGING_ALERT_TOPIC_ARN` (the topic) set
  (owner).

## 3. Clear the old list (go 2: deletes, permanent from the site's view)

As the owner, while `servicesRepair` is on:
`aws s3api delete-object --bucket <BucketName> --key <key>` for
`v1/services.json`, `v1/services.json.sig`, `v1/services/1.json` and
`v1/services/1.json.sig`. Each leaves a delete marker, and the old
objects stay in the bucket's version history.

Then `aws cloudfront create-invalidation --distribution-id <DistributionId> --paths '/v1/services.json*' '/v1/services/*'`
(the copies are cached for a year).

`v1/p/` stays: its proposals' services are the same, so they still check
against the new list. Until step 6, uploads are refused (there is no
list), and the monitor fails (expected).

## 4. Redeploy: no repair, the new site key (go 3)

As the publish role, `./votesctl site-key -kms <SiteSigningKeyArn>`
prints the new site key; `./votesctl list-anchor-key -kms <ListAnchorKeyArn>`
prints the list anchor key's SPKI.

The same deploy as step 1 **without** `servicesRepair` (and without the
variable), and with `-c siteKey=<the new key>`. Then check the live bucket
policy, not `cdk diff`: `aws s3api get-bucket-policy --bucket <BucketName>`
has no `ServicesRepairKeepsVersions`, and `PublishedNeverDeleted` names
both `v1/p/*` and `v1/services/*`.

## 5. The pins PR (go 4: a merge, with the owner's GitHub approval)

One PR, merged before the publish, so the new keys have an independent
pin:
- `monitor.yml`, staging's row: `default_key: <the new key>`,
  `list_anchor_pub: <the SPKI>`, `first_logged: "1"`,
  `log_required: true`;
- the nits carried from votes #36 (GC #13026);
- this document, with the keys written into step 6's command.

## 6. Before the publish (read-only, GC #13003)

All four say `staging`; stop at any mismatch:
- [ ] the deploy context's `sigstore`;
- [ ] the list anchor key's `vettid:sigstore` tag;
- [ ] the `-sigstore` flag in step 7's command;
- [ ] `monitor.yml`'s staging row (`sigstore: staging`).

Also: `v1/services.json`, its `.sig`, `v1/services/1.json` and
`v1/services/1.bundle` are all 404 through the site.

## 7. Publish version 1 (go 5)

`services.json`: the services of the old version 1, with `"version": 1`
and `"previous"` the base64 of 32 zero bytes.

As the publish role (`AWS_PROFILE=votes-publish-staging`):
`./votesctl publish-services -kms <SiteSigningKeyArn> -site-key <the new key, from the pins PR> -watch-topics <KeyWatchTopicArn>,<KeyWatchTopicBArn> -list-anchor-key <ListAnchorKeyArn> -list-anchor-pub <the SPKI, from the pins PR> -sigstore staging -bucket <BucketName> -in services.json`

Expected:
- two signatures (the site key and the list anchor key), each emailed
  four times;
- `v1/services/1.bundle`, then `v1/services.json.sig` and
  `v1/services.json`, then the version copies.

On any failure, run the same command with the same file (README). Then a
manual `monitor` run is green: `"log": "from version 1"`, one bundle
logged.

## 8. The vaults (the other session; its own go)

A vettid-vault staging release with `vote_site_key` = the new key
(`enclave/releasecfg/staging.json`). The test phones re-enroll and the
test connections are re-invited (Rule 3); no vault migrates its old list.

## 9. The secret (go 6)

Once steps 7 and 8 hold and the monitor is green: schedule the deletion
of `vettid-votes-staging/site-key` (the longest window), as the owner.
The `-secret` path, and the migration-only paths, go in their own PR.

## Done when

Staging serves a KMS-signed version 1 with its bundle; the monitor is
green with the log pinned from version 1; the staging release pins the
new `vote_site_key`; and the old secret is scheduled for deletion.
