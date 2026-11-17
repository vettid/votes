# Staging: the votes site starts fresh under its KMS keys

**Status:** draft runbook, GC #12656 (plan #12646, step 5). Rule 3 (GC
#r58: no backward compatibility before production users) and the owner's
choice a (GC #13144) replace the planned migration. The staging service
list starts again at version 1, **byte for byte the list served today**,
signed with the KMS site key and logged in Rekor from the start. The
owner runs every deploy, deletion and publish, each with its own go. The
vettid-vault staging release is the other session's, with its own go.
Production has its KMS keys from its first deploy and needs none of this.

**State when this was written (read-only checks, 2026-11-17):**
- `VotesSite-staging` was last updated 2026-11-03. None of votes #33–#36
  is deployed: no KMS keys or aliases, no `PublishRoleArn` or
  `ListAnchorKeyArn` outputs, no termination protection, no
  `MonitorRoleArn`.
- `vettid-votes-staging-api` runs with `VOTES_SIGSTORE=staging` and
  `VOTES_SITE_KEY=c4dqg2ssGVylbO9Xnpdv4zopmzx9S++4KgxMWOyhXJQ=` (the
  secret's key).
- The site serves service list version 1 under that key, with no bundle.
  `v1/services/1.json` and `v1/services.json` are the same bytes,
  SHA-256 `62bde9054bad1ef16a7693ab0eb775bf4ad7238a2796477e8240331574bd36ee`.
- The index lists two proposals, both closed and with results published.
- The trail is an organization trail, homed in `us-east-1`, logging all
  management events.
- The secret `vettid-votes-staging/site-key` exists and isn't scheduled
  for deletion.

**Values used below.** Set these in the shell you run the steps from:

```sh
S="--profile vault-staging --region us-east-1"   # the owner's staging admin profile
BUCKET=votessite-staging-bucket83908e77-bppc9pn4gncf
DIST=E2U8AQVDFFZZDH
OLD_KEY=c4dqg2ssGVylbO9Xnpdv4zopmzx9S++4KgxMWOyhXJQ=
ALARM_TOPIC=arn:aws:sns:us-east-1:<staging account>:vettid-org-staging-vault-alerts
```

The code deployed and built is votes `main` at or after `c98a713`
(votes #36), the same commit for every step: `go build -o votesctl ./cmd/votesctl`
at the root, and `npm ci` in `cdk/`.

**What the key watch emails, step by step.** Until step 2b confirms them,
the two watch subscriptions are pending and nothing reaches the watch
topics. The key-use alarm and the monitor's failures also go to
`vettid-org-staging-vault-alerts` (the alarm topic).
- **Step 2:** two "AWS Notification - Subscription Confirmation" emails
  (one per watch topic), and possibly a key-use alarm on the alarm topic
  (the deploy creates the watched aliases). **Never click the link in
  those emails**: confirm only as in 2b, or `ConfirmationWasAuthenticated`
  is false and every publish is refused.
- **Step 2b:** the `ConfirmSubscription` calls are watched; the first
  events emailed may be these.
- **Step 4** (the first deploy with the watch confirmed): the stack's
  `CreateChangeSet` and `ExecuteChangeSet`, each matched by a pair of
  rules and sent to two topics (four emails each), and a key-use alarm.
  **That is the deploy, not an incident.**
- **Step 5's tests:** each test call emailed four times.
- **Step 9:** two signatures (the site key's and the list anchor key's),
  four emails each, and a key-use alarm.
- **Steps 3 and 6:** nothing (S3, CloudFront and Secrets Manager aren't
  watched).

## 1. Before the first go

**Owner prerequisites, once (README "Deployment"):**
- [ ] The IAM Identity Center permission set `VettIDVotesPublisher`
  (GC #12713). Its only permission is an inline policy allowing
  `sts:AssumeRole` on `arn:aws:iam::<staging account>:role/vettid-votes-staging-publish`;
  assign it in the staging account to the owner alone. Its role's ARN
  (`aws iam list-roles $S --path-prefix /aws-reserved/sso.amazonaws.com/`)
  is `PUBLISHER`.
- [ ] A GitHub OIDC provider in the staging account (there is none):
  `aws iam create-open-id-connect-provider $S --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com`.
  Its ARN is `OIDC`.
- [ ] `keyWatchEmail` in `~/.cdk.json` on the deploying machine, never in
  the tracked `cdk.json` or shell history.

**Preconditions, just before step 2:**
- [ ] No vote in progress: `curl -s https://votes.staging.vettid.org/v1/index.json`
  lists no proposal open or waiting for results. The service-vault session
  opens none until step 9's monitor run is green.
- [ ] The list to publish again, saved now, while it is still served:
  `curl -s https://votes.staging.vettid.org/v1/services/1.json -o services.json`,
  and `sha256sum services.json` is `62bde905…bd36ee` as above.

## 2. Deploy, with deletes allowed under `v1/services/` (go 1)

From `cdk/`, with `VOTES_SERVICES_REPAIR=confirm` in the environment:

```sh
npx cdk deploy $S -c envName=staging -c hostName=votes.staging.vettid.org -c hostedZoneId=<id> \
  -c zoneName=vettid.org -c sigstore=staging -c siteKey=$OLD_KEY -c publisherPrincipalArn=$PUBLISHER \
  -c alarmTopicArn=$ALARM_TOPIC -c githubOidcProviderArn=$OIDC -c servicesRepair=true
```

**2b. Confirm the watch at once** (a minute, before step 3), from the
token in each confirmation email, without clicking its link:

```sh
aws sns confirm-subscription $S --topic-arn <KeyWatchTopicArn> --token <token> --authenticate-on-unsubscribe true
aws sns confirm-subscription $S --topic-arn <KeyWatchTopicBArn> --token <token> --authenticate-on-unsubscribe true
```

Then `aws sns get-subscription-attributes $S --subscription-arn <each>`
says `"ConfirmationWasAuthenticated": "true"`.

**The publish role**, for steps 4, 7 and 9: add to `~/.aws/config`

```ini
[profile votes-publish-staging]
role_arn = <PublishRoleArn>
source_profile = <your VettIDVotesPublisher profile>
region = us-east-1
```

## 3. Clear the old list (go 2: deletes; the site serves no list until step 9)

Re-check the index first (no vote in progress). Then, as the owner:

```sh
for k in v1/services.json v1/services.json.sig v1/services/1.json v1/services/1.json.sig; do
  aws s3api delete-object $S --bucket $BUCKET --key $k
done
aws cloudfront create-invalidation $S --distribution-id $DIST --paths '/v1/services.json*' '/v1/services/*'
```

Each delete leaves a delete marker, and the old objects stay in the
bucket's version history. `v1/p/` stays: its proposals bind only their
service's identity and anchor keys, which the new list keeps. From here
until step 9, uploads are refused (there is no list), and the hourly
monitor fails, alerting the alarm topic (expected).

## 4. Redeploy: no repair, the new site key (go 3)

As the publish role (`AWS_PROFILE=votes-publish-staging`):

```sh
./votesctl site-key -kms <SiteSigningKeyArn>          # NEW_KEY
./votesctl list-anchor-key -kms <ListAnchorKeyArn>    # SPKI
```

The same deploy as step 2 **without** `servicesRepair` (and without
`VOTES_SERVICES_REPAIR`), and with `-c siteKey=$NEW_KEY`. Then check the
live bucket policy, not `cdk diff`: `aws s3api get-bucket-policy $S --bucket $BUCKET`
has no `ServicesRepairKeepsVersions`, and `PublishedNeverDeleted` names
both `v1/p/*` and `v1/services/*`.

Steps 2 to 4 run back to back, so deletes under `v1/services/` are
allowed for minutes only.

## 5. After the deploy (README "After the first deploy")

- [ ] A test `UpdateEventBus` on the default bus (its description, put
  back as it was) is emailed (owner).
- [ ] A call only a nested match catches is emailed, e.g. a `PutRule`
  rewriting a `-b` rule's description as it was (owner).
- [ ] The log group `/vettid/votes/staging/key-use` has the lines of
  steps 2b to 5 (the `aws:SourceArn` condition lets the rules write).
- [ ] `aws kms list-resource-tags --key-id <ListAnchorKeyArn>` as the
  publish role: `vettid:sigstore` = `staging`.
- [ ] `aws s3api get-object --bucket $BUCKET --key v1/services/9.json /dev/null`
  as the publish role is a 404.
- [ ] Repository variables `VOTES_STAGING_MONITOR_ROLE_ARN` (output
  `MonitorRoleArn`) and `VOTES_STAGING_ALERT_TOPIC_ARN` (`$ALARM_TOPIC`)
  set (owner).

Not done here: breaking the feed on purpose (the feed heartbeat, GC
#12987, will cover it); a separate test signature (step 9's publish is
the first, and is emailed and alarmed).

## 6. Schedule the old secret's deletion (go 4)

Nothing needs it any more, and it isn't watched:
`aws secretsmanager delete-secret $S --secret-id vettid-votes-staging/site-key --recovery-window-in-days 30`.

## 7. The pins PR (go 5: a merge, with the owner's GitHub approval)

One PR, merged before the publish, so the new keys have an independent
pin:
- `monitor.yml`, staging's row: `default_key: <NEW_KEY>`,
  `list_anchor_pub: <SPKI>`, `first_logged: "1"`, `log_required: true`;
  and its header, and the README's text on the first pin, for a fresh
  start;
- `.gitleaks.toml`: the new key, and the SPKI if gitleaks flags it, as
  narrow allowlist entries with a comment (each is public);
- the nits carried from votes #36 (GC #13026);
- this document, with `NEW_KEY` and `SPKI` written into step 9's command.

## 8. Before the publish (read-only)

- [ ] **The instance (GC #13003).** All four say `staging`: the deploy
  context's `sigstore`, the list anchor key's `vettid:sigstore` tag,
  step 9's `-sigstore`, and `monitor.yml`'s staging row.
- [ ] **The site key.** All four are `NEW_KEY`: the function's
  `VOTES_SITE_KEY`
  (`aws lambda get-function-configuration $S --function-name vettid-votes-staging-api`),
  `monitor.yml`'s staging `default_key`, step 9's `-site-key`, and what
  step 10's release will pin.
- [ ] **The old list is gone.** The invalidation is `Completed`
  (`aws cloudfront get-invalidation $S --distribution-id $DIST --id <id>`),
  then `v1/services.json`, its `.sig`, `v1/services/1.json` and
  `v1/services/1.bundle` are 404 through the site.
- [ ] **The list.** `sha256sum services.json` is still `62bde905…bd36ee`.
- [ ] **No vote in progress** (the index, again).

## 9. Publish version 1 (go 6: public and permanent)

**This is public and permanent:** `v1/services/1.json`, `.sig` and
`.bundle` are write-once, and the Rekor entry can never be removed.

As the publish role (`AWS_PROFILE=votes-publish-staging`):

```sh
./votesctl publish-services -kms <SiteSigningKeyArn> -site-key <NEW_KEY> \
  -watch-topics <KeyWatchTopicArn>,<KeyWatchTopicBArn> -list-anchor-key <ListAnchorKeyArn> \
  -list-anchor-pub <SPKI> -sigstore staging -bucket $BUCKET -in services.json
```

It writes `v1/services/1.bundle`, then `v1/services.json.sig` and
`v1/services.json`, then the version copies. On any failure, run the
same command with the same file (README). Then a manual `monitor` run is
green: `"log": "from version 1"`, one bundle logged.

## 10. The vaults (the other session; its own go)

A vettid-vault staging release with `vote_site_key` = `NEW_KEY`
(`enclave/releasecfg/staging.json`). The list's bytes are unchanged, so
a vault holding the old version 1 confirms it under the new key: **no
reset is needed for votes.** Between steps 9 and 10, phones on the old
release log `vote.list_rejected` (the new signature isn't under the key
they pin): expected. Test connections are re-invited only if something
else needs it (Rule 3).

## 11. After

The `-secret` and migration-only paths, including the stack's retained
secret construct, go in their own PR (GC #12657).

## Done when

Staging serves a KMS-signed version 1 (today's bytes) with its bundle;
the monitor is green with the log pinned from version 1; the staging
release pins the new `vote_site_key`; and the old secret is scheduled
for deletion.
