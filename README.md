# votes.vettid.org

The public record of VettID votes. Every proposal, extension and
result of a vote run through a
[VettID service vault](https://github.com/vettid/service-vault) is
published here, anchored in Sigstore's Rekor transparency log, and never
changed once published. Members' vaults learn of proposals here, and
anyone can check a vote's results from here alone.

The protocol is
[BALLOT-PROTOCOL](https://github.com/vettid/service-vault/blob/main/docs/BALLOT-PROTOCOL.md)
(§3.3 is this site's contract). The site's design is
[docs/VOTES-SITE.md](docs/VOTES-SITE.md).

## Status

The upload API (`site/`, `cmd/votes-api`), its storage on S3, the
operator's `votesctl` and the CDK stack (`cdk/`) are written. Staging
runs at `https://votes.staging.vettid.org` (2026-10-29); production is
not deployed.

## Checking a vote

Anyone can check a vote from what the site serves (BALLOT-PROTOCOL
§8.4), with the site's public key (in the member vaults' release config:
staging's is `vote_site_key` in vettid-vault's
`enclave/releasecfg/staging.json`):

```sh
go build -o votesctl ./cmd/votesctl
./votesctl check -site-key <base64> <proposal_id>
./votesctl check -all -site-key <base64>   # the service list and every proposal
# staging: -site https://votes.staging.vettid.org -sigstore staging
```

It fetches the service list, the proposal, its extensions and the
results with their rows, signatures and Sigstore bundles, and puts each
document, in order, through the upload API's own checks on an empty
store, at the time its anchor shows. So it checks every signature, each
anchor in Rekor under the service's registered anchor key, the timing as
anchored (the proposal and each extension timestamped before the close
they precede, the results after collection ended; when each was uploaded
is the site's word), the extensions (numbered without gaps, 24 at most,
exactly those the results list, each with the signature it was
published with), the results against the rows and
the tags, and the upload API's request rules (each part present, the
signature's length, the size limits). It prints a JSON report or fails with the first check that
didn't hold. The report's `status` is `open` (before the close in force
plus a minute), `closed` (after it, with no results published: not yet,
or withheld), or `counted` (with the tally and counts, among them `unhandled`: messages
of the voting window the count went ahead without, each of which may
have held a ballot); `hashes` are
each document's SHA-256, for readers to compare what they were served;
`partial` names a document whose signature or bundle is there without
it (an upload not finished); `listing` names each way `index.json` or
the month's archive differs from the documents (such as
`index: closes_at` or `archive: missing`; the index may drop a vote 30
days after its close; an entry from before the site listed `unhandled`
lacks it, which isn't reported); `skew_seconds` is, for each anchor, its
RFC 3161 time less the time Rekor logged it. Only a 404 is taken as not
published.

**`ok`** is false when the report has `mismatches`: a `listing`
difference still there 10 minutes after the latest document's anchor
time (the lists are rewritten just after each document, so they may lag
an upload in progress), a `partial` upload 10 minutes after its bundle's
timestamp (a signature alone: after its `Last-Modified`; a bundle that
doesn't verify, or no date at all: at once), or an anchor whose two
times differ by more than 10 minutes. `partial_objects` lists each
partial upload's served objects, by `key` and hex `sha256`. A partial
upload that can never be completed (an extension past its close;
`partial_permanent`) can be acknowledged: `-acknowledged <file>` reads a
JSON array of `{proposal_id, document, reason, acknowledged_at,
objects}`, where `objects` is the partial's `[{key, sha256}]` as the
report's `partial_objects` gives them (for the monitor,
`monitor/acknowledged-<env>.json`, each entry added by PR with its
reason; VOTES-SITE §7). A permanent partial it lists is reported in
`acknowledged`, not as a mismatch, only while the objects served for it
are exactly those listed: a changed hash, an added object or a missing
one is a mismatch. An entry that matches no permanent partial upload
(completed, still retryable, or wrong) is a mismatch too.
**`-all`** also walks the service
list's kept versions, `services/1.json` to the current one, checking
each signature and that each extends the one before, then checks every
proposal in `index.json` and the archive (from 2026-10, or
`-since YYYY-MM`), and prints one report with each proposal's, a failed
one as its `error`. A network error or a `5xx` is retried twice.

**Exit codes:** `0` every check held and `ok` is true; `1` a check failed,
or a file it was given couldn't be read (with `-all`, after the report;
it wins over `3`); `2` a usage error; `3` the checks held but `ok` is
false. The `monitor` workflow runs `check -all` hourly on staging and
production and fails on `1` or `3` (VOTES-SITE §7; it needs the
repository variable `VOTES_PROD_SITE_KEY` before production is checked).
A failed run is published to the alert topic, and a successful one puts
a heartbeat whose alarm fires after 3 hours without one ("Deployment",
step 6).

**The service list's Rekor log:** with `-all`,
`-list-anchor-pub <base64 SPKI> -first-logged <version>` (both, or
neither) also check that every version from the first logged one on has
a bundle that verifies under that key for its bytes, and that no bundle
sits past the current version (VOTES-SITE §7). The report's
`services.log` says `from version <n>` and `services.logged` how many
bundles verified, or `not pinned`. The `monitor` workflow takes both from
`list_anchor_pub` and `first_logged` in its own matrix, pinned by PR
before each environment's first publish with `-kms`, with
`first_logged: "1"` (a fresh list: staging started fresh under its KMS
keys, docs/STAGING-FLAG-DAY.md). Until then it warns, or, with
`log_required` (staging since its fresh start, production), fails once
the site key is set. `-list-anchor-pub` must be a P-256 key's
SubjectPublicKeyInfo and `-first-logged` a decimal version from 1; a pin
past the real first logged version (the version before it has a bundle)
is a mismatch, and a `-first-logged` past the current version is an
error.

**Production's site key** is a repository variable today
(`VOTES_PROD_SITE_KEY`), and its check is skipped with a warning while
it is unset; at production's launch, pin it in the workflow's matrix
(`default_key`) and empty its `key_var`, by PR, as staging's is, along
with its list anchor key. A row with an empty `key_var`, or with a log
pin, fails the run without a site key.

**The trusted root:** Sigstore's, for `-sigstore` (`production` by
default), fetched through its TUF repository, or, if that fails, the one
embedded in the build, provided it is at most 90 days old
(`site/roots/embedded_at`; refresh with `go generate ./site` and commit
the result). The report's `trusted_root` says which (`tuf`, `embedded`
or `file`). `-trusted-root <file>` uses a Sigstore trusted root file
instead.

## Deployment

Deploys need the owner's go. The stack is `VotesSite-<envName>` in
`cdk/`, always in `us-east-1` (CloudFront's certificate must be there).
The deploying machine needs Node 22 and Go: the function is built at
synth by `scripts/build-api.sh`, the build CI hashes.

Every deploy passes, from `cdk/` after `npm ci`:
`-c envName=<staging|prod> -c hostName=<name> -c hostedZoneId=<id> -c zoneName=vettid.org -c sigstore=<staging|production> -c publisherPrincipalArn=<role ARN> -c alarmTopicArn=<SNS topic ARN> -c githubOidcProviderArn=<ARN> -c keyWatchEmail=<address>`,
where `sigstore` matches the service vaults' `SV_SIGSTORE` for that
environment; `publisherPrincipalArn` is the role, in this account, of
the publisher's own IAM Identity Center permission set (below, "The
publisher is a permission set of its own"): the only principal that may
assume the publish role; `alarmTopicArn` and `githubOidcProviderArn` are step 6's;
and `keyWatchEmail` is where the key watch sends each event directly
(below; it is in the deployed template, never in this repository). None
has a default.

1. **Once per account:** `npx cdk bootstrap aws://<account>/us-east-1`.
2. **First deploy:** `npx cdk deploy <context> -c firstDeploy=true`.
   It makes the bucket, the function, the API, the certificate, the
   CloudFront distribution, the name's records and the site key in KMS
   (output `SiteSigningKeyArn`). Uploads are refused until step 4.
3. **The site key:** build votesctl (`go build -o votesctl ./cmd/votesctl`
   at the root), then `./votesctl site-key -kms <SiteSigningKeyArn>`
   (as the publish role, below) prints its public key. It also goes in the
   member vaults' release config (BALLOT-PROTOCOL §3.3).
4. **Deploy again** with `-c siteKey=<that key>`, and pass it on every
   deploy from then on (a deploy without it is refused).
5. **The service list:** `services.json` holds

   ```json
   {"v": 1, "version": 1, "previous": "<base64 of 32 zero bytes>",
    "services": [{"service_id": "<hex>", "name": "<name>", "iks": ["<base64 ik>"],
                  "anchor_keys": [{"key": "<base64 SPKI>", "anchor_cert": "<base64>", "ik": "<base64 ik>"}]}]}
   ```

   with each service's identity keys, and its anchor key and certificate
   from the service vault's `GET /v1/anchor-key`. Each later list has the
   next `version` and, as `previous`, the base64 SHA-256 of the published
   `v1/services.json`. Publish it with
   `./votesctl publish-services -kms <SiteSigningKeyArn> -site-key <that key> -watch-topics <KeyWatchTopicArn>,<KeyWatchTopicBArn> -list-anchor-key <ListAnchorKeyArn> -list-anchor-pub <its pinned key> -sigstore <the stack's sigstore> -bucket <BucketName> -in services.json`,
   as the publish role.
   It takes the key's ARN only, never an alias, and uses the
   ARN's region; it refuses a key that isn't an Ed25519 signing key
   whose public key is `-site-key`. **Take `-site-key` from an
   independent pin** (the stack's deployed `siteKey`, or `vote_site_key`
   in the member vaults' release config), never from `site-key -kms`
   itself, which would only compare the key with itself. It refuses to
   publish unless `-watch-topics` names the stack's two key watch
   topics (in that order, in the key's account and region) and each has
   exactly one email subscription, confirmed by a signed-in call
   (`ConfirmationWasAuthenticated`) and with no filter policy (README
   "The watch"), since nobody would be told of the signature. Every check that can
   refuse the list (its form, the first-list rule, that it extends the
   published list by one version, and that no other bytes sit at its
   version's copy) runs before it is signed, so no signature is made, or
   emailed, for a list that is refused; a rerun of a list already signed
   (published, interrupted half-way, or with its copy kept) uses the
   bucket's signature and signs nothing (so republishing a version
   rolled back, whose signature is kept, makes no KMS call and no email:
   it was emailed when it was made). A signature can still go
   unpublished, and so be emailed for nothing, only when something fails
   after it is made: a transient S3 error, another publish winning the
   conditional write, the 3-minute deadline passing, or KMS's answer
   being lost. Each costs an email, never a wrong publish; run the same
   command again. It signs through KMS once (no
   retry: run it again if it fails), `ED25519_SHA_512` over the label
   and the list's SHA-256, checks the signature under `-site-key` before
   anything is written, and gives up after 3 minutes.

   **Each list is logged in Rekor** (VOTES-SITE §3, GC #12646 task 3):
   once signed, and before it is moved, its SHA-256 is signed with the
   list anchor key (`-list-anchor-key`, by ARN only, in the site key's
   account and region; an ECDSA P-256 key, since Rekor takes no pure
   Ed25519), timestamped and entered in Rekor on the `-sigstore`
   instance, in the Rekor profile of BALLOT-PROTOCOL §8.5. The bundle is
   checked under that instance's trusted root and kept write-once as
   `v1/services/<version>.bundle`, before the signature and the list, so
   that no list is served without its entry.

   Before anything is signed it checks:
   - the key's public key is `-list-anchor-pub` (its SubjectPublicKeyInfo,
     base64). **Take it from an independent pin**, the monitor's
     `list_anchor_pub` in `.github/workflows/monitor.yml`. The first
     time, print it with
     `./votesctl list-anchor-key -kms <ListAnchorKeyArn>` (as the publish
     role) and pin it there by PR, with `first_logged: "1"` and the new
     site key as `default_key`, with the owner's go, before the first
     publish;
   - `-sigstore` is the stack's: the key's tag `vettid:sigstore`, which
     the stack sets to its `sigstore` (a change of the tag is watched).
     **On this refusal, don't change `-sigstore` to match the tag**: an
     administrator could have retagged the key. Check the stack's
     `sigstore` (the deploy context) and the key watch's mail for a
     `TagResource` first;
   - the published list's own bundle verifies on that instance under that
     key. A published list without one is refused ("version N is current
     without its bundle"): run the command with that version's list first, which
     logs it with no new site signature;
   - a bundle already kept for this version anchors this list. One that
     anchors anything else is refused (clear it as a stray, below); one
     that does is used, so a rerun logs nothing again.

   A Rekor entry is public and permanent: a list is logged only after it
   has passed every check and the site key has signed it. **After a
   failed publish, run the same command with the same file.** If
   logging failed, nothing was written, and the site key signs again (so
   that publish is emailed twice); and if Rekor had already accepted the
   entry (the failure came after it: a lost answer, the bundle's check,
   or its write), the list anchor key signs again too, and Rekor holds a
   second entry for the same list (a search of entries is to match them by
   the list's SHA-256, so that is no mismatch). So every version has a
   bundle.

   To act as the publish role, add a profile and set
   `AWS_PROFILE` to it:

   ```ini
   [profile votes-publish-<env>]
   role_arn = <PublishRoleArn>
   source_profile = <your Identity Center profile>
   ```

   Each publish is emailed (twice) and raises the key-use alarm: that is
   the watch working.
   Each version is also kept, write-once, as `v1/services/<version>.json`
   and `.sig`, for vaults that missed versions; running the command again
   with the list that is already published writes its copy if it is
   missing (as for a list published before copies were kept).
   A list that drops anything the published one had is refused, and so
   is one outside BALLOT-PROTOCOL §3.3's bounds (a name of 1–100 bytes,
   4,194,304 bytes in all; the number of services and keys is not
   limited, since the list only grows); one interrupted half-way is
   finished by running the same command again.
6. **The monitor's alerts** (VOTES-SITE §7): every deploy passes
   `-c alarmTopicArn=<SNS topic ARN in us-east-1> -c githubOidcProviderArn=<ARN>`
   (required since the site's signing keys, whose alarms go there too). The provider is the
   account's existing one for `token.actions.githubusercontent.com`
   (`aws iam list-open-id-connect-providers`); the stack doesn't make
   one. If the account has none, create it once, outside the stack
   (`aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com --client-id-list sts.amazonaws.com`).
   The deploy makes the role `vettid-votes-<env>-monitor` (output
   `MonitorRoleArn`) and the heartbeat alarm. Then set the repository
   variables (Settings, Variables: not secrets)
   `VOTES_<STAGING|PROD>_MONITOR_ROLE_ARN` to that output and
   `VOTES_<STAGING|PROD>_ALERT_TOPIC_ARN` to the topic. The alarm fires 3
   hours after the deploy until the first run that puts a heartbeat.

### The site's signing keys

The stack also makes two KMS keys, made inside KMS so that they can
never be exported (VOTE-SITE-KEY-COMPROMISE §6, GC #12646), and the role
`vettid-votes-<env>-publish` (output `PublishRoleArn`), which only
`publisherPrincipalArn` may assume, for an hour at a time:

- the **site key** `alias/vettid-votes-<env>-site` (Ed25519, output
  `SiteSigningKeyArn`), which is to sign the service list, and
- the **list anchor key** `alias/vettid-votes-<env>-list-anchor` (ECDSA
  P-256, output `ListAnchorKeyArn`), which logs each list in Rekor
  (`publish-services -list-anchor-key`).

Their key policies let the publish role alone sign, each key with its
own algorithm only (`ED25519_SHA_512`, `ECDSA_SHA_256`; `kms:Sign` is
denied to every other principal), allow no grants, and let only the
account's root user schedule their deletion. The account keeps
administering them: **any administrator of the account** (any principal
whose IAM policies allow it) may change a key policy, so that the keys
can't be locked out; no one gets `Sign` that way, and such a change is
watched (below). The publish role may read each key's public key, its
description and its tags (the list anchor key's tag `vettid:sigstore` is
the stack's `sigstore`, which `publish-services` checks), read and write
`v1/services.json`, `v1/services.json.sig` and `v1/services/*`, and list
the bucket (so that a missing copy is a 404; every document is public),
and nothing else.

**The watch.** Six EventBridge rules, three pairs
(`vettid-votes-<env>-kw-keys`, `-kw-watch` and `-kw-notify`, each with
its `-b`; split so that each pattern stays under EventBridge's
2,048-character quota), with the same targets, every one watching all
six (so switching one off is seen), send every event they match to the
log group `/vettid/votes/<env>/key-use`, kept for good, and **directly
to two topics, `vettid-votes-<env>-key-watch` and
`vettid-votes-<env>-key-watch-b`**, each emailing `keyWatchEmail` on its
own subscription, so that no alarm sits between an event and a person
and a subscription removed from one is told on the other. Both are
email, so both reach the same inbox: a second kind of notifier is the
cross-account forward (below). Only the six rules may publish to them
(and CloudWatch alarms of the account). The rules, the topics and the
subscriptions are kept if removed from the stack (the topic, log and
queue policies, the alarms and the queue are not), and the stack has
termination protection. They match:

- every signature with either key, and every grant, key policy change,
  alias change, tag change, deletion or disabling of either key or its
  alias;
- every change to the publish role (its trust or permission policies, a
  boundary, its deletion);
- every change to the watch: its rules and targets, its alarms (enabling
  or disabling their actions too), any alarm mute rule, its log group,
  streams, metric filter and key, any log group resource policy, its dead
  letters, the alarm topic and the two watch topics and their
  subscriptions (a data protection policy too);
- every update, change set, stack policy, termination protection
  change, rollback or deletion of this stack, since one update can
  change all of the watch (so a deploy is emailed too), any stack
  refactor, and any change set run by its ARN alone (no stack name);
- every change to any event bus (`UpdateEventBus`: a key put on the
  default bus, then disabled, could stop the rules);
- every change to any CloudTrail trail (stopping or starting it,
  deleting it, or changing what it records): the watch gets every event
  from CloudTrail.

Each event has the operation, what it acted on (the key, role, rule,
alarm, topic, subscription, log group, stack or queue), the caller's identity
type, role and temporary key id (traceable to its `AssumeRole` in
CloudTrail) and the CloudTrail event id: never the session name, which
is an email address. Any logged line also raises the alarm
`vettid-votes-<env>-key-use` (counted by samples, so a value anyone puts
in its namespace can only raise it), and a delivery that fails after
EventBridge's retries goes to the queue `vettid-votes-<env>-key-use-dlq`
and raises `vettid-votes-<env>-key-use-feed`; both alarms notify the
alarm topic and both watch topics, so silencing one path is told on
another.

- **Confirm both watch subscriptions** after the first deploy, from the
  token in each email AWS sends, so that unsubscribing needs a signed-in
  call (which is watched), not a link in the email:
  `aws sns confirm-subscription --topic-arn <KeyWatchTopicArn or KeyWatchTopicBArn> --token <token> --authenticate-on-unsubscribe true`.
  Until then the watch emails no one. Then check that each says
  `ConfirmationWasAuthenticated` `true`
  (`aws sns get-subscription-attributes --subscription-arn <arn>`): a
  confirmation or an unsubscribe by the email's link is not in
  CloudTrail, so the watch can't see it. Keep `keyWatchEmail` in
  `~/.cdk.json`, not the tracked `cdk.json`, and out of shell history.
- **The deploy that brings the `vettid:sigstore` tag** (GC #12646 task
  3) tags the list anchor key: if the key already exists, expect a
  `TagResource` mail on both watch topics for it. That is the deploy, not
  an incident; any other `TagResource` or `UntagResource` on either key
  is one.
- **A publish with `-kms` is two signatures (the site key's and the list
  anchor key's), each logged twice and emailed four times** (a pair of
  rules, two topics: four lines and eight emails), and raises the key-use
  alarm; a rerun that finds the list already signed and logged makes
  none; **a deploy of this stack does
  too** (it updates the watch). **A publish that does not means the feed
  is broken: stop publishing and find out why.**
- The feed needs CloudTrail's management events (read and write) for
  `us-east-1` in the account, from a trail that is logging and is
  **homed in `us-east-1`, or an organization trail**: a trail homed in
  another region can be stopped by a call there, which this watch (in
  `us-east-1`) doesn't see. An organization trail can be stopped from
  the management account, also outside this watch.
- EventBridge retries a failed delivery for up to 24 hours before it
  goes to the dead letters, so the feed alarm can come that late. While
  any dead letter remains, the feed alarm stays in ALARM: read them, then
  purge the queue (a watched call).
- **A known limit (staging):** the watch is in the same account as the
  keys, so an administrator of the account who cuts every path in one
  CloudFormation update, or in calls quicker than the watch reports (a
  filter policy on a subscription, then disabling the alarms' actions),
  can sign unseen until the change is noticed. Each list is logged in
  Rekor (task 3 of GC #12646), and the monitor checks hourly, from
  outside AWS, that the current list and every kept version from the
  first logged one on have their entries at the time of the check
  (VOTES-SITE §7). It doesn't catch a list served between two runs and
  then removed with no kept copy, nor a bundle made after the fact by
  someone who can sign with the list anchor key (its Rekor time isn't
  compared with when the list was served). A list signed and logged but served somewhere other than
  this site needs a search of Rekor under the list anchor key, which is
  its own task, designed first (GC #12980). **Production waits for
  the cross-account forward** (the owner's choice c, GC #12690): every
  watched event also sent to the management account, where the staging
  or production account's administrators can't silence it, before a
  production key signs anything. A heartbeat that proves the feed is
  alive (a scheduled watched call, and an alarm when its line is
  missing) is its own task, not yet built.
- **The publisher is a permission set of its own** (GC #12713). Before
  the first deploy, the owner creates in IAM Identity Center a permission
  set (for example `VettIDVotesPublisher`) whose only permission is an
  inline policy allowing `sts:AssumeRole` on
  `arn:aws:iam::<account>:role/vettid-votes-<env>-publish`, and assigns it
  in this account to their own user alone: **its assignment list is the
  access list** (every user or group assigned it shares its role).
  `publisherPrincipalArn` is that set's role in this account
  (`aws iam list-roles --path-prefix /aws-reserved/sso.amazonaws.com/`,
  the role named `AWSReservedSSO_VettIDVotesPublisher_<hash>`); the stack
  refuses any other kind of role. No name or address of the owner goes
  in the template. If the set is reprovisioned, the trust no longer
  matches (the publish role can't be assumed, which fails closed): deploy
  again with the new role's ARN. MFA is enforced by Identity Center at
  sign-in; the trust policy can't test it for those sessions.
- **A first deploy that rolls back** leaves the two keys (they are
  retained) with their aliases gone: schedule their deletion as the root
  user, or leave them, disabled, before deploying again.
- **After the first deploy of an environment, check** (with the owner):
  a trail as above is logging (its home region, or that it is an
  organization trail); both subscriptions' `ConfirmationWasAuthenticated`
  is `true`; a test `UpdateEventBus` on the default bus (its description,
  say) is emailed; so is a call that only a nested match catches (a
  `SetSubscriptionAttributes` on a watch subscription, putting back the
  value it had, or a `PutRule` that rewrites a `-b` rule's description
  as it was), which shows EventBridge took the nested patterns; a test signature with the publish role
  is logged twice, emailed four times and raises the alarm, and names the
  role and no session; whether a refused `Sign` by another principal is
  logged (note it if not); that the log resource policy's `aws:SourceArn`
  condition lets the rules write (the lines arrive at all); that breaking
  the feed (for example, removing the log resource policy for a moment)
  is emailed and raises the feed alarm; and that `GetObject` of a missing
  `v1/services/<n>.json` under the publish role is a 404.

### Clearing a stray version copy

The bucket policy keeps everything under `v1/services/` write-once and
never deleted (VOTES-SITE §2). If an object that isn't that version's
signed list lands at a version's key (say, a manual upload with the
wrong number), `publish-services` refuses every later list. To clear it,
with the owner's go for each step:

1. Deploy with the usual context plus `-c servicesRepair=true`, with
   `VOTES_SERVICES_REPAIR=confirm` in the environment (synth refuses the
   flag without it, so a value left in `cdk.json` can't stay on). Synth
   warns while it is set. Every key under `v1/services/` can then be
   deleted; their object versions still can't, and puts still need
   `If-None-Match`.
2. Delete only the stray keys, e.g.
   `aws s3api delete-object --bucket <BucketName> --key v1/services/<n>.json`
   (and `.sig`; or `v1/services/<n>.bundle`, for a stray bundle). This leaves a delete marker; the stray stays in the
   bucket's version history. A wrong key hides a good copy, which
   `publish-services` doesn't rewrite unless it is the current version's:
   restore one with `get-object --version-id <its version>` and
   `put-object --if-none-match '*'`.
3. Deploy again **without** `servicesRepair` (and without the variable),
   then check the live policy, not `cdk diff`, which reads the same
   context: `aws s3api get-bucket-policy --bucket <BucketName>` must have
   no `ServicesRepairKeepsVersions`, and `PublishedNeverDeleted` must
   name both `v1/p/*` and `v1/services/*`.
4. Run `publish-services` again; it writes the missing copy.
5. If the stray was ever fetched through the site, CloudFront may still
   serve it: `aws cloudfront create-invalidation --distribution-id
   <DistributionId> --paths '/v1/services/<n>.json*'`.

## License

AGPL-3.0 (see [LICENSE](LICENSE)).
