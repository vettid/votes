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
   CloudFront distribution, the name's records and the site key's
   secret (output `SiteKeySecret`). Uploads are refused until step 4.
3. **The site key:** build votesctl (`go build -o votesctl ./cmd/votesctl`
   at the root), then `./votesctl site-key -secret <SiteKeySecret>`
   prints its public key. It also goes in the member vaults' release
   config (BALLOT-PROTOCOL §3.3).
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
   `./votesctl publish-services -secret <SiteKeySecret> -bucket <BucketName> -in services.json`.
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
  P-256, output `ListAnchorKeyArn`), which is to log each list in Rekor.

Their key policies let the publish role alone sign, each key with its
own algorithm only (`ED25519_SHA_512`, `ECDSA_SHA_256`; `kms:Sign` is
denied to every other principal), allow no grants, and let only the
account's root user schedule their deletion. The account keeps
administering them: **any administrator of the account** (any principal
whose IAM policies allow it) may change a key policy, so that the keys
can't be locked out; no one gets `Sign` that way, and such a change is
watched (below). The publish role may read and write `v1/services.json`,
`v1/services.json.sig` and `v1/services/*`, and list the bucket (so that
a missing copy is a 404; every document is public), and nothing else.

**The watch.** Two EventBridge rules with one pattern and the same
targets (each sees a change to the other) send every event they match
to the log group `/vettid/votes/<env>/key-use`, kept for good, and
**directly to two topics, `vettid-votes-<env>-key-watch` and
`vettid-votes-<env>-key-watch-b`**, each emailing `keyWatchEmail` on its
own subscription, so that no alarm sits between an event and a person
and a subscription removed from one is told on the other. Only the two
rules may publish to them (and CloudWatch alarms of the account). The
rules, topics and subscriptions are kept if removed from the stack, and
the stack has termination protection. They match:

- every signature with either key, and every grant, key policy change,
  alias change, deletion or disabling of either key or its alias;
- every change to the publish role (its trust or permission policies, a
  boundary, its deletion);
- every change to the watch: its rules and targets, its alarms (enabling
  or disabling their actions too), any alarm mute rule, its log group,
  streams, metric filter and key, any log group resource policy, its dead
  letters, the alarm topic and the two watch topics and their
  subscriptions (a data protection policy too);
- every update, change set, stack policy, termination protection change
  or deletion of this stack, since one update can change all of the
  watch (so a deploy is emailed too);
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
  Until then the watch emails no one. Keep `keyWatchEmail` in
  `~/.cdk.json`, not the tracked `cdk.json`, and out of shell history.
- **A publish is two signatures, each sent twice** (four lines and four
  emails) and raises the key-use alarm; **a deploy of this stack does
  too** (it updates the watch). **A publish that does not means the feed
  is broken: stop publishing and find out why.**
- The feed needs CloudTrail's management events (read and write) for
  `us-east-1` in the account, from a trail that is logging: one homed in
  `us-east-1`, a multi-region trail, or an organization trail.
- EventBridge retries a failed delivery for up to 24 hours before it
  goes to the dead letters, so the feed alarm can come that late. While
  any dead letter remains, the feed alarm stays in ALARM: read them, then
  purge the queue (a watched call).
- **What is not covered:** an administrator of the account who cuts
  every path in one CloudFormation update, or in calls quicker than the
  watch reports, can sign unseen until the change is noticed (the
  owner's question, GC #12690). A heartbeat that proves the feed is alive
  comes with the monitor (GC #12646, task 4).
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
  a trail as above is logging; a test signature with the publish role
  is logged twice, emailed twice and raises the alarm, and names the
  role and no session; whether a refused `Sign` by another principal is
  logged (note it if not); that the log resource policy's `aws:SourceArn`
  condition lets the rules write (the lines arrive at all); that breaking
  the feed (for example, removing the log resource policy for a moment)
  is emailed and raises the feed alarm; and that `GetObject` of a missing
  `v1/services/<n>.json` under the publish role is a 404.

Until the staging flag day, `votesctl` still signs with the secret's key
(GC #12646, tasks 2 to 5).

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
   (and `.sig`). This leaves a delete marker; the stray stays in the
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
