# Staging flag day: the site key moves to KMS

**Status:** draft runbook, GC #12656 (plan #12646, step 5). The owner runs
every deploy, publish and deletion, each with its own go. The vettid-vault
staging release is the other session's, with its own go. Nothing here is
for production: production has its KMS keys from its first deploy and no
flag day.

**State when this was written (read-only checks, 2026-11-17):**
- `VotesSite-staging` was last updated 2026-11-03. None of votes #33–#36
  is deployed: no KMS keys or aliases, no `PublishRoleArn` or
  `ListAnchorKeyArn` outputs, no termination protection, no
  `MonitorRoleArn`.
- `vettid-votes-staging-api` runs with `VOTES_SIGSTORE=staging`.
- The site serves service list **version 1**, under the secret's key,
  with no bundle. So the flag day publishes **version 2**.
- The trail is an organization trail, homed in `us-east-1`, logging all
  management events.
- The secret `vettid-votes-staging/site-key` exists and isn't scheduled
  for deletion.

## 0. Before the go

**Code, merged:**
- [ ] `check -all` across the site-key change (the plan task proposed in
  GC #13081): without it, the monitor fails from step 6 on.

**Owner prerequisites, once (README "Deployment"):**
- [ ] The IAM Identity Center permission set `VettIDVotesPublisher`
  (GC #12713). Its only permission is an inline policy allowing
  `sts:AssumeRole` on `arn:aws:iam::<staging account>:role/vettid-votes-staging-publish`.
  Assign it in the staging account to the owner alone. Note its role's
  ARN (`aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/`):
  that is `publisherPrincipalArn`.
- [ ] A GitHub OIDC provider in the staging account (there is none):
  `aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com`.
  Its ARN is `githubOidcProviderArn`.
- [ ] `keyWatchEmail` in `~/.cdk.json` on the deploying machine, never in
  the tracked `cdk.json` or shell history.
- [ ] `alarmTopicArn`: the existing topic `vettid-org-staging-vault-alerts`.

## 1. Deploy (go 1)

From `cdk/` after `npm ci`, with the usual context plus the new keys:
`npx cdk deploy -c envName=staging -c hostName=votes.staging.vettid.org -c hostedZoneId=<id> -c zoneName=vettid.org -c sigstore=staging -c siteKey=<the current key, unchanged> -c publisherPrincipalArn=<step 0> -c alarmTopicArn=<step 0> -c githubOidcProviderArn=<step 0>`
(`keyWatchEmail` from `~/.cdk.json`).

`siteKey` stays the secret's key here: the site still serves version 1
under it until step 6.

Expect the deploy itself to be watched: the stack update, and the list
anchor key's `TagResource`, are emailed on both watch topics. That is the
deploy, not an incident.

## 2. After the deploy (README "After the first deploy")

Read-only, unless marked:
- [ ] Both watch subscriptions confirmed from their emails' tokens with
  `--authenticate-on-unsubscribe true` (owner), then
  `ConfirmationWasAuthenticated` is `true` on each.
- [ ] A test `UpdateEventBus` on the default bus (its description, put
  back as it was) is emailed (owner).
- [ ] A call only a nested match catches is emailed, e.g. a `PutRule`
  rewriting a `-b` rule's description as it was (owner).
- [ ] The log group's lines arrive (the resource policy's `aws:SourceArn`
  lets the rules write).
- [ ] `GetObject` of a missing `v1/services/9.json` as the publish role is
  a 404.
- [ ] `aws kms list-resource-tags` on `ListAnchorKeyArn`, as the publish
  role: `vettid:sigstore` = `staging`.
- [ ] Repository variables `VOTES_STAGING_MONITOR_ROLE_ARN` (output
  `MonitorRoleArn`) and `VOTES_STAGING_ALERT_TOPIC_ARN` (the topic) set
  (owner), and a manual run of `monitor` is green.

## 3. The pins PR (go 2: a merge, with the owner's GitHub approval)

As the publish role:
`./votesctl site-key -kms <SiteSigningKeyArn>` (the new site key) and
`./votesctl list-anchor-key -kms <ListAnchorKeyArn>` (the list anchor key's SPKI).

One PR, reviewed before anything is signed, so the new keys have an
independent pin:
- `monitor.yml`, staging's row: `list_anchor_pub: <SPKI>`,
  `first_logged: "2"`, `log_pending: true`, `log_required: true`, and the
  key change: `default_key: <the new key>`,
  `previous_site_key: <the secret's key>`, `key_changed_at: "2"`. Each
  list, `services.json` included, verifies under the key for its
  version, so the monitor stays green before and after the publish.
- The nits carried from votes #36 (GC #13026).
- This document, with the new site key written in step 6's command.

After the merge, a manual `monitor` run is green (the log pins are
pending: nothing logged yet).

## 4. Before the publish (read-only, GC #13003)

All four say `staging`; stop at any mismatch:
- [ ] the deploy context's `sigstore`;
- [ ] the list anchor key's `vettid:sigstore` tag;
- [ ] the `-sigstore` flag in step 6's command;
- [ ] `monitor.yml`'s staging row (`sigstore: staging`).

Also: the site still serves version 1, under the secret's key.

## 5. The list

`services.json` for version 2: version 1's services, unchanged,
`"version": 2`, and `"previous"` the base64 SHA-256 of the published
`v1/services.json` bytes.

## 6. Publish version 2 (go 3)

As the publish role (`AWS_PROFILE=votes-publish-staging`):

`./votesctl publish-services -kms <SiteSigningKeyArn> -site-key <the new key, from the pins PR> -previous-site-key <the secret's key> -watch-topics <KeyWatchTopicArn>,<KeyWatchTopicBArn> -list-anchor-key <ListAnchorKeyArn> -list-anchor-pub <the SPKI, from the pins PR> -sigstore staging -bucket <BucketName> -in services.json`

Expected:
- two signatures (the site key and the list anchor key), each emailed
  four times;
- `v1/services/2.bundle`, then `v1/services.json.sig` and
  `v1/services.json`, then the version copies.

On any failure, run the same command with the same file (README).

**From here until step 7, uploads to the site are refused**: the site
still checks lists under the secret's key (the owner's Q2 a). Keep the
gap short.

## 7. Redeploy with the new site key (go 4)

The same deploy as step 1, with `-c siteKey=<the new key>`.

Then a PR (go 5) that removes `log_pending` from `monitor.yml`. Until it
merges, the hourly monitor alerts ("the pin is still pending"), which is
expected.

## 8. The vaults (the other session; its own go)

A vettid-vault staging release with `vote_site_key` = the new key
(`enclave/releasecfg/staging.json`). Until then, staging vaults reject
version 2. A vault more than one version behind stalls until it is reset
(the owner's Q2 a; no real members).

## 9. The secret (go 6)

Once steps 6–8 hold and the monitor is green: schedule the deletion of
`vettid-votes-staging/site-key` (the longest window), as the owner. Then
the plan's last step removes the `-secret` path (votes PR 5).

## Done when

Staging serves KMS-signed lists, each with its bundle; the monitor is
green with `log_pending` removed; the staging release pins the new
`vote_site_key`; and the old secret is scheduled for deletion.
