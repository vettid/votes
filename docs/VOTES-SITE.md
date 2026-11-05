# votes.vettid.org

**Status:** 0.2.12 (2026-11-04), draft. The protocol this site serves is
[BALLOT-PROTOCOL](https://github.com/vettid/service-vault/blob/main/docs/BALLOT-PROTOCOL.md)
(0.11.0); its §3.3 is this site's contract and §8.5 has the document
schemas. Where this document and the protocol differ, the protocol wins
and this document is corrected.

## 1. What it is for

- Members' apps learn of proposals here, without the organisation's
  service.
- Every document of a vote (the proposal, any extensions, the results)
  is here, the same for every reader, and never changes once published.
- Observers check a vote from here alone (BALLOT-PROTOCOL §8.4).

The site is run by VettID, separately from every service vault. It holds
no keys that sign votes, no member data and no sessions, and keeps no
record of who reads what. It can withhold a document, but not alter
one: the service's signature and the Rekor anchor catch that.

## 2. Architecture

| Part | What it is |
|---|---|
| Bucket | Private S3 bucket, versioned, blocking public access. Read only through CloudFront (origin access control). Written only by the upload function, which cannot delete. |
| CloudFront | `votes.vettid.org`. Serves `/v1/*` from the bucket and `/api/*` from the API. Security headers as vettid.org's sites. No access logs. Behind an AWS WAF web ACL with one rate rule (§4, "Limits"). |
| Upload API | API Gateway HTTP API → Lambda `votes-api` (Go, arm64). |
| Service list | `services.json`, kept by VettID's operator (a service is added by the owner, BALLOT-PROTOCOL §3.3), not in this repository. The operator's `votesctl publish-services` signs it with the site's Ed25519 key and writes it to the bucket as `v1/services.json` and `.sig`, refusing a list that doesn't extend the published one, and keeps each version as `v1/services/<version>.json` (§3): the bucket's copies are the record of every list. The function reads it on every upload and checks it under the site's public key whenever its bytes or its signature's differ from the pair it checked last. |
| Stack | CDK (TypeScript), `VotesSite-staging` and `VotesSite-prod`, as member-service. |

**(chosen; not in the spec:** Lambda rather than an ECS service, because
uploads are a few per vote. The function is a reproducible build,
`scripts/build-api.sh`: CI prints its sha256 for each commit, and the
binary a deploy ships has the same hash.)

**Write-once** is the bucket's conditional write: every document is put
with `If-None-Match: *`. A `412` means the path exists: the function
compares the bytes and answers `200` if they are equal and `409` if not.
The bucket policy enforces it for every principal, the operator's
included: under `v1/p/` and `v1/services/` (the kept versions of the
service list) a put or copy without `If-None-Match` and any delete are
denied, and so is a multipart upload (its parts carry no condition). The
current `services.json` and its `.sig` are outside both; a publish
replaces them in place. A stray object at the next version's key can't
be removed, and `publish-services` refuses a copy that holds other bytes;
clearing one takes a recovery deploy (`servicesRepair`, with the owner's
go), which allows deletes under `v1/services/` until the next deploy
without it but
still keeps every object version (README, "Clearing a stray version
copy").

## 3. Paths

All under `https://votes.vettid.org/v1/`.

| Path | Contents | Cache |
|---|---|---|
| `services.json`, `.sig` | The service list and the site's signature (BALLOT-PROTOCOL §3.3, §8.5). The two are separate objects, so while a publish moves them a reader may get a list and a signature of different versions; the cache is short so that a retry soon gets the matching pair | 10 s |
| `services/<version>.json`, `.sig` | Every version of the service list that has been the current one, with its signature, written once just after it becomes current (`<version>` in decimal; the current version's copy may lag it briefly). Versions are consecutive, so for a vault holding version `h` the app fetches `h+1` to the current version in order, and each chains to the one before. A copy that is missing yet (404) is retried later | 1 year, immutable |
| `index.json` | Proposals open or closed within the last 30 days: `[{proposal_id, service_id, proposal_hash, opens_at, closes_at, extended, published, unhandled?}]`, by `opens_at`; `unhandled` is the results' `counts.unhandled`, once they are published | 60 s |
| `archive/<YYYY-MM>.json` | Every proposal by the month of `opens_at`, same entries | 60 s |
| `p/<proposal_id>/proposal.json`, `.sig`, `.sigstore.json` | The proposal, `proposal_sig` (raw 64 bytes), its anchor bundle | 1 year, immutable |
| `p/<proposal_id>/extension-<n>.json`, `.sig`, `.sigstore.json` | An extension | 1 year, immutable |
| `p/<proposal_id>/results.json`, `.sig`, `.sigstore.json` | The results | 1 year, immutable |
| `p/<proposal_id>/rows.json` | The rows, which `results.json` names by hash | 1 year, immutable |

## 4. Upload API

`POST https://votes.vettid.org/api/v1/p/<proposal_id>/<name>`, where
`<name>` is `proposal`, `extension-<n>` or `results`. The body is JSON
`{doc: b64, sig: b64, bundle: <Sigstore bundle JSON>, rows?: b64}`, with
`rows` for the results only. There is no other
credential: the service's signature is the authentication.

**Checks, in order** (each failure is `422` with an error code):
1. **Service:** for a proposal, its `service` key is on the service
   list; for anything else, the proposal is already here.
2. **Bytes:** the document is canonical JCS and matches its schema; its
   `proposal_id` is the path's.
3. **Signature:** under the proposal's `service` key, with the
   document's label (BALLOT-PROTOCOL §3.1, §8.5, §7).
4. **Anchor:** the bundle verifies with Sigstore's own verifier
   (`sigstore-go`) against the trusted root of the stack's Sigstore
   instance (staging or production): the ECDSA signature over the
   document under one of the service's listed anchor keys, the Rekor
   entry and its inclusion proof, and one RFC 3161 timestamp. **The
   trusted root** is fetched through the instance's TUF repository when
   the function starts, and again at most once every 24 hours; a fetch
   that fails, or takes over 5 seconds, keeps the root in use. Both
   instances' roots are also embedded in the build, with the time they
   were fetched (`site/roots/embedded_at`; refreshed with
   `go generate ./site`): a start whose fetch fails runs on the embedded
   root, unless it is over 90 days old, when the start fails (and so
   does every upload) until the repository answers or a build with a newer
   root is deployed. `votesctl check` does the same.
5. **Order and fields:**
   - a proposal: anchored, and uploaded, before its `closes_at`; the
     same proposal again is accepted at any time (a retry);
   - an extension: `n` is the next number, it is anchored and uploaded
     before the `closes_at` it extends, never once results are
     published, and the total is within 24 h;
   - results: uploaded and anchored at least a minute after the final
     `closes_at`, when collection ends (BALLOT-PROTOCOL §7); they pass the observer's check (BALLOT-
     PROTOCOL §8.4) and contain the published proposal and extensions
     byte for byte, each with its published signature: the `sig` the
     results carry for the proposal, and for each extension, is byte
     for byte its published `.sig` (another valid signature of the same
     document is refused, `sig_mismatch`); and `rows` hashes to their
     `rows_hash`.
6. **Write-once** (§2): the signature, the bundle and any rows go up
   first and the document last, so a document is never there without
   them; a retry fills in what a failed upload left out. Anything an
   earlier upload left at those paths must belong to this document: the
   same signature and rows, or a bundle that verifies for it (another
   anchor of the same bytes is the same document); anything else is
   `409`.

Before these, the request is refused if it is over the size for its
kind (a proposal 256 KiB, an extension 4 KiB, results 512 KiB, a bundle
64 KiB; extensions are numbered at most 24), and the bundle must be in the protocol's profile: v0.3, a
SHA-256 message signature under a public key, exactly one `hashedrekord`
0.0.1 entry and exactly one RFC 3161 timestamp. Documents nest at most 8
deep. The index is updated on every accepted upload, retries included,
so that one a failure left undone is finished.

Then the function updates `index.json` and the archive with a
conditional write on their ETag, retrying on a conflict.

**Answers:** `201` published, `200` already published with the same
bytes, `409` a different document is published there, `422` a check
failed, `413` too large, `503` another store failure. The body is
`{"published": "<name>", "index_updated": true}`. If the document was
written but the index update failed, the answer is still `201` (or `200`
for a re-upload), with `"index_updated": false` and the failure logged:
the document exists and the index is stale. The index is not rebuilt
from the stored documents; it is repaired by the next write for the
same proposal (an extension or the results add the proposal's entry if
it is missing) or by uploading the same bytes again, which runs the
index update again. An identical re-upload is not refused for already
existing, though it can still get `422` (for example `unknown_service`)
or `503`; a different document for the same path is `409`. Readers must
not rely on the index's `extended` count to know which `extension-<n>`
files exist: fetch `extension-<n+1>` until a `404`. Extensions are
published in order, so there is no gap, but a `404` (which `/v1/*` may
cache for a short time) only means none yet: check again later.

**Size:** a request is at most 6 MB (Lambda's limit). A results row is
about 250 bytes, so that holds about 20,000 eligible members. Larger
votes need a two-step upload through the bucket; not in 0.2.0.

**Limits:** the HTTP API's stage throttle, for the whole stage and not
per route or per client: 10 requests a second, bursts of 20, beyond
which API Gateway answers `429`. In front of it, an AWS WAF web ACL on
the CloudFront distribution with one rate-based rule: at most 100
requests in any 5 minutes from one IP address to a path starting with
`/api/` (after URL-decoding and normalizing it, as CloudFront routes
it), beyond which that address's requests there are answered `429`
(`{"error":"rate_limited"}`, not WAF's default `403`, since a client
retries a `429` and takes a `403` as final) until its rate falls below
the limit. Everything else is allowed. The
ACL keeps CloudWatch metrics only: request sampling is off, so it keeps
no source addresses (§5).

## 5. What the site keeps about readers

Nothing. CloudFront access logs are off. The WAF counts requests per
address only for its rate rule's window, with no logging and no request
sampling; the addresses its rule is blocking at the moment can be read
through the WAF API while the block lasts, and are gone after. API Gateway access logs carry the route, status, size and
latency, never the source address. The function logs ids, types, sizes
and error codes.

## 6. Deployment

- The domain: an ACM certificate and an alias record in the vettid.org
  hosted zone, which the vettid.org stacks own.
- Deploys need the owner's go, as for the service vault and
  member-service.

## 7. Monitoring

`votesctl check -all` (README, "Checking a vote") checks what the site
serves, as an observer, and is run hourly against staging and
production by the `monitor` workflow (`.github/workflows/monitor.yml`),
which fails on exit code 1 or 3. It takes staging's site key from the
member vaults' release config, and production's from the repository
variable `VOTES_PROD_SITE_KEY` (skipped, with a warning, until it is
set); `VOTES_STAGING_SITE_KEY` overrides staging's. It also warns when
the embedded trusted roots are over 60 days old. GitHub mails a failed
run only to whoever last changed the cron line, and disables a schedule
after 60 days without activity in the repository, so each run also
reports to AWS (**Alerts**, below).

- **The service list's chain:** `services/1.json` to the current
  version's copy, each with its `.sig` under the site key, each holding
  its version and extending the one before (the first with an all-zero
  `previous`), the current copy byte for byte `services.json`. A copy
  that doesn't verify or chain is an error; a missing copy, or one past
  the current version, is a mismatch, except the current version's copy
  in the 10 minutes after `services.json` was last modified (its
  `Last-Modified`), as it is written just after the list (§3).
- **Every proposal** in `index.json` and in the archive's months, from
  the site's first (2026-10, or `-since`) to the current one and those
  of the index's entries, each checked as `votesctl check <id>` does.
- **Mismatches** make the report's `ok` false: a `listing` difference
  still there 10 minutes after the latest document's anchor time; a
  `partial` upload 10 minutes after its bundle's RFC 3161 time, or, for
  a signature alone (the site writes the signature, then the bundle),
  10 minutes after the signature's `Last-Modified`; one whose bundle
  doesn't verify, or a signature alone with no `Last-Modified`, can't be
  dated and is a mismatch at once; and an anchor
  whose RFC 3161 time and Rekor integrated time differ by more than 10
  minutes, or that has no integrated time (`skew_seconds` has each
  difference). A service anchors and uploads within seconds, so either
  gap means a failed upload not yet retried, a clock that is off, or a
  timestamp held back before it was logged. A partial extension whose
  close has passed, or after the results, can never be completed: the
  report lists it in `partial_permanent`, and it stays a mismatch on
  every run until it is acknowledged.
- **Acknowledged partial uploads:** `monitor/acknowledged-staging.json`
  and `-prod.json` (passed with `-acknowledged <file>`) are strict JSON
  arrays of entries

  ```json
  {"proposal_id": "<id>", "document": "extension-2", "reason": "<why>",
   "acknowledged_at": "YYYY-MM-DD",
   "objects": [{"key": "v1/p/<id>/extension-2.json.sig", "sha256": "<hex>"}]}
  ```

  with no other members. `objects` names the partial's served objects
  (its `.json.sig`, its `.json.sigstore.json`, and the document, of
  those that exist), each by key, under `v1/p/<proposal_id>/` and one of
  that document's three, and by the SHA-256 of the bytes served, 64
  lowercase hex digits; at least one, none twice. A permanent partial
  upload is reported in `acknowledged`, and is not a mismatch, only while
  the objects served for it are exactly the entry's: one missing, one
  added (say, a bundle at the same name), or one whose hash differs makes
  the entry a mismatch that names each difference, and the partial stays
  one. Another partial of the same proposal isn't covered. An entry that
  matches no permanent partial upload (completed, still retryable, or
  wrong) is a mismatch, so the list stays true. Each entry is added by a
  PR that gives its reason; both lists start empty. On `main` a change
  needs a pull request with one approving review, and `.github/CODEOWNERS`
  makes the owner's review required for `monitor/`, the monitor's
  workflow and the embedded trusted root (`site/roots/`). **The hashes:** the
  report's `partial_objects` lists, for each partial upload, its served
  objects as the entry takes them (`key` and `sha256`), so an entry is
  copied from the failing run's report; or, by hand,
  `curl -s https://<site>/<key> | sha256sum` for each key.
- **Fetches:** a network error or a `5xx` is retried twice (after 1 and
  3 seconds) before it counts as a failed check; with `-all`, an index
  or archive month that can't be read or parsed is an error in the
  report (`lists`), which is still printed, with the rest checked.
- **Exit codes:** `0` every check held and `ok` is true; `1` a check
  failed, or an argument file (`-acknowledged`, `-trusted-root`) or the
  trusted root couldn't be read (with `-all`, a failed check's report is
  printed first, with each failure in it as `error`; this takes
  precedence over `3`); `2` a usage error; `3` the checks held but `ok`
  is false (mismatches). A Rekor request that still fails (`rekor.error`,
  **The Rekor check**) is neither a failed check nor a mismatch until
  `failures` reaches 3: alone, it leaves `0`, and the heartbeat is put.
- **Alerts:** a stack deployed with `alarmTopicArn` (an SNS topic in the
  stack's region, `us-east-1`) and `githubOidcProviderArn` (the account's
  existing OIDC provider for `token.actions.githubusercontent.com`; the
  stack takes it, as an account has one, and makes none) has a role,
  `vettid-votes-<env>-monitor` (output `MonitorRoleArn`). Only GitHub's
  OIDC tokens with audience `sts.amazonaws.com`, subject
  `repo:vettid@168311946/votes@1438447065:ref:refs/heads/main` (the
  repository uses GitHub's immutable subjects, with the owner's and the
  repository's ids) and `job_workflow_ref`
  `vettid/votes/.github/workflows/monitor.yml@refs/heads/main` may assume
  it, and it may only `sns:Publish` to that topic and
  `cloudwatch:PutMetricData` in its environment's namespace
  `VettID/Votes/<env>`. Each run,
  on main, assumes it with `aws-actions/configure-aws-credentials`. A
  failed run (a mismatch, a failed check, or a step before it) publishes
  to the topic, naming the environment, the exit code and the run. A run
  whose check succeeded puts the heartbeat: `MonitorHeartbeat` in
  `VettID/Votes/<env>`, dimension `env`, value 1. The stack's alarm
  `vettid-votes-<env>-monitor-heartbeat` (the hourly sum below 1 for 3
  hours in a row, missing data breaching) notifies the same topic, and
  again when it clears: it catches a schedule GitHub disabled, runs that
  can't reach AWS, a skipped check (production before its site key is
  set), and failures that go on. The role and the topic are the
  repository variables `VOTES_<STAGING|PROD>_MONITOR_ROLE_ARN` and
  `VOTES_<STAGING|PROD>_ALERT_TOPIC_ARN` (not secrets); while either is
  unset the run warns and sends nothing. A stack without the two
  contexts has neither the role nor the alarm.

**The Rekor check** (`-rekor`, with `-all`; the choices marked below
are the owner's (a) of 2026-11-05) looks in Rekor for anchors the
site doesn't show. The profile's `hashedrekord` 0.0.1 entries (§4) are
only in Rekor v1: `rekor.sigstore.dev` for production and
`rekor.sigstage.dev` for staging, as `-sigstore`. The `monitor` workflow
runs it hourly with the rest. `-rekor` refuses `-since` (a usage error):
the older proposals' digests would be left out. The anchor keys are
every key in every service's `anchor_keys` on the current list (the
list keeps past ones), each compared by its SubjectPublicKeyInfo
(SPKI, DER), never by PEM bytes. An entry is named by its entry ID, 80
lowercase hex digits (the tree ID's 16 and the leaf hash's 64), and
matched by its last 64, which stay the same whichever shard ID Rekor
prefixes. The report's `rekor` holds the checkpoint, the counts, each
entry reported (`unknown`, `pending`, `acknowledged`), `warnings`,
`error`, `failures` and `mismatches`.

- **The checkpoint:** the active shard's signed checkpoint (`GET
  /api/v1/log`: origin, tree ID, tree size and root hash), verified
  under the log's key in the trusted root (§4 item 4). If the state
  (below) holds one of the same tree ID, a consistency proof from it
  (`GET /api/v1/log/proof`) must verify. A smaller tree, another root at
  the same size, or a proof that fails, all with the same tree ID, is a
  mismatch (`rekor: inconsistent`) and the recorded checkpoint is kept,
  so every later run reports it too; a consistent one replaces it. The
  run also proves consistency from the newest published bundle's
  checkpoint (its inclusion proof's, in its own shard), which needs no
  state, so a state rolled back or reset can't take the check below it.
  v1 checkpoints have no witness cosignatures, so this shows only that
  the log never contradicts what this monitor and the site's bundles saw
  before.
- **Shards:** a tree ID other than the state's is its own mismatch,
  `rekor: shard changed`, on every run until the owner accepts it: a
  `workflow_dispatch` run with the input `rekor_accept_shard` set to the
  new tree ID passes `-rekor-accept-shard <tree ID>`, which requires the
  recorded tree among `GET /api/v1/log`'s `inactiveShards`, its
  checkpoint consistent with that shard's, and then records the new
  shard's. An entry in an inactive shard is verified against that
  shard's checkpoint and tree, with `treeID` passed to
  `/api/v1/log/proof`. A log index is the index within its shard plus
  the sizes of the shards before it (`inactiveShards`; all of them for
  the active shard).
- **The search** (production's check, **the owner's choice**, a2 of
  2026-11-05, its limit stated below; the alternatives are a full scan, as staging's, of millions of entries
  a day, or no check of production, staging's alone): for each anchor
  key, `POST /api/v1/index/retrieve`
  `{"publicKey":{"format":"x509","content":"<base64 PEM>"}}`. Rekor
  marks it deprecated and best-effort: its results may be incomplete. It
  also indexes a `hashedrekord` key exactly as submitted
  (`sha256(PublicKey.Content)`), while the search hashes the canonical
  value, so an entry made with the key in another PEM form, or inside a
  certificate, is logged but not returned (**Not guaranteed**).
- **Each entry found** is fetched (`POST /api/v1/log/entries/retrieve`,
  10 entry IDs a request) unless the verified store (below) holds it,
  and verified before its digest is used: a `hashedrekord` 0.0.1 entry
  over a `sha256` digest naming an anchor key, its ECDSA signature over
  the digest under that key, its signed entry timestamp and inclusion
  proof under the log's key, the proof's checkpoint the run's or
  consistent with it (its shard's, for an inactive shard), and an
  integrated time not after the run. One under an anchor key that is
  anything else (another kind or version, a `sha384` or `sha512`
  digest), or that fails, is a mismatch (`rekor: unverified`), whatever
  its digest.
- **Unknown digests:** a verified entry whose digest is no known
  document's is a mismatch (`rekor: unknown digest`). A digest is the
  `sha256` of a document's bytes, never of its `.sig`. Those known are
  the run's: each proposal's, extension's and results' `hashes`, the
  documents a partial upload's bundle anchors (already reported as
  `partial`), the served document bytes of each acknowledged partial
  upload (its `partial_objects`), and each service-list version's (never
  expected under an anchor key, as the site key signs the list). One
  integrated less than 10 minutes (`ListingGrace`) before the run (0 ≤
  run − integrated < 10 min) is `pending`, not a mismatch, as its upload
  may not be done; one integrated after the run is `unverified` (above).
  An anchor that will never be published (an upload the site refused, a
  test) is a mismatch on every run until it is acknowledged.
- **Anchored again:** a known digest may be anchored more than once (a
  retried upload). An entry for one integrated more than 24 hours after
  the published bundle's is a warning (`rekor.warnings`, and in the
  run's log), not a mismatch: the anchor key is in use.
- **Staging's scan:** on staging only, the check also reads every entry
  of the active shard from the tree size scanned last to the run's, 10
  by log index a request (about 14,000 entries a day, so some 60
  requests a run), and keeps every entry, of any kind, whose key or
  certificate carries an anchor key's SPKI (compared as SPKI, never as
  PEM bytes), each verified and compared as above. One the search didn't
  return, though integrated before the search began, is a mismatch,
  `rekor: index gap` **(the owner's (a) of 2026-11-05: an alarm, not a
  warning)**: the search is production's only check, so a sign that it
  misses entries has to reach someone, and a warning in the run's log
  reaches no one. Production gains millions of entries a day and is
  never scanned.
- **Search unavailable:** a network error, a `429` or a `5xx` is retried
  within the run (**Pacing**). A search, checkpoint or proof that still
  fails is `rekor.error` and adds one to `failures` in the state, which
  a run that completes resets. Below 3 it is neither a failed check nor
  a mismatch: the run exits `0` if the rest held, and puts the
  heartbeat. At 3 consecutive runs it is a mismatch, `rekor: search
  unavailable` **(the owner's (a) of 2026-11-05: 3, as the heartbeat alarm's
  3 hours: an outage of an hour or two, within Rekor's 99.5%
  availability objective, passes, and one that lasts is raised as soon
  as a stopped monitor would be)**. A `404` or `410` from the search
  (the endpoint is gone, as in Rekor v2) is the mismatch at once.
- **Pacing:** Rekor's rate limits are undocumented. Requests go one at
  a time, at least 250 ms apart, at most 1,000 an instance a run; a
  network error, a `429` or a `5xx` is retried after 1, 2, 4 and 8
  seconds (longer if `Retry-After` says so). At the cap the run stops:
  the scan resumes next run from where it stopped, and a search or fetch
  left undone is a mismatch, `rekor: incomplete` (an alarm, not `search
  unavailable`: it says the work outgrew the cap, not that Rekor is
  down).
- **The verified store:** each verified entry is kept by entry ID, with
  its log index, digest and integrated time, so a run fetches only the
  entries it hasn't verified, and compares every stored one's digest as
  above. It is `-rekor-verified <file>`, between runs the S3 object
  `rekor-verified.json` in the monitor's bucket,
  `vettid-votes-<env>-monitor`, which the stack adds (private,
  versioned, blocking public access, kept when the stack is deleted).
  Not SSM: it grows with the anchors, and a standard parameter's 4 KB
  holds some 20 entries, an advanced one's 8 KB some 40. The monitor
  role may only `s3:GetObject` and `s3:PutObject` it.
- **Acknowledged entries:** `monitor/rekor-acknowledged-staging.json`
  and `-prod.json` (passed with `-rekor-acknowledged <file>`), beside
  the partial uploads' lists, whose entries name a document and not a
  Rekor entry, are strict JSON arrays of entries

  ```json
  {"instance": "staging", "uuid": "<hex>", "log_index": 123,
   "sha256": "<hex>", "reason": "<why>", "acknowledged_at": "YYYY-MM-DD"}
  ```

  with no other members. `instance` is `-sigstore`'s, `uuid` the entry's
  80-hex entry ID as Rekor gives it (lowercase), matched by its last 64,
  `log_index` its log index, and `sha256` its digest, 64 lowercase hex
  digits; none twice. An unknown digest is reported in `acknowledged`,
  and is not a mismatch, only for the entry all four name. Each run
  fetches every listed entry by entry ID: one that isn't there, whose
  log index or digest differs, or that isn't signed by an anchor key is
  a mismatch, so the list stays true. Only unknown digests are
  acknowledged, never a failed verification or an index gap. As with
  the other lists, each entry is added by a PR that gives its reason,
  the owner reviews it (`.github/CODEOWNERS` covers `monitor/`), and
  both start empty; the report's `unknown` has each entry's fields to
  copy.
- **The state:** the monitor kept none before. `-rekor-state <file>` is
  read at the start and rewritten at the end: JSON `{"v": 1, "origin":
  "<origin>", "tree_id": n, "tree_size": n, "root_hash": "<hex>",
  "scanned_to": n, "failures": n}` (`scanned_to` on staging only).
  Between runs it is the SSM parameter
  `/vettid/votes/<env>/monitor/rekor-state` (standard, well under its
  4 KB). SSM holds no empty value, so the stack creates it holding the
  sentinel `{"v":1,"bootstrap":true}`, and only if it is absent: a
  custom resource puts it with `Overwrite: false` on create (ignoring
  `ParameterAlreadyExists`), does nothing on update and keeps it on
  delete, so no deploy rewrites the state. An empty or sentinel state is
  a mismatch, `rekor: no state`, unless the run is given
  `-rekor-bootstrap` (a `workflow_dispatch` run with the input
  `rekor_bootstrap`, owner-run), which records the checkpoint it finds
  and starts staging's scan at the current tree size; the newest
  bundle's checkpoint (above) still binds it. The monitor role may only
  `ssm:GetParameter` and `ssm:PutParameter` it, and never delete it.
  Not GitHub's cache or artifacts: the cache is evicted after 7 days
  unused and artifacts expire, while the parameter lasts and only this
  workflow, on `main`, can write it. A run without the state (another
  branch, or the role unset) checks no consistency from it, counts no
  failures and says so (`rekor.state` `none`).
- **Reading and writing back:** the workflow assumes the role before
  the check (it now does so after) for a read-only session, narrowed by
  an inline session policy to `ssm:GetParameter` and `s3:GetObject`,
  reads the state and the verified store into files, and runs the check
  under it. A separate step after it assumes the role again with the
  write permissions and puts both back whenever the check step ran,
  whatever its exit code (`!cancelled()`). A run past the job's
  20-minute timeout is cancelled and writes nothing: the next starts
  from the state before it, and the heartbeat alarm covers a hang. The
  read, change and write aren't atomic: they rely on the workflow's
  `concurrency: monitor` group (`cancel-in-progress: false`), which runs
  one run at a time, each environment with its own parameter and object.
- **Alarms:** each `rekor:` mismatch makes `ok` false (exit 3), so the
  failed run's alert goes to the topic (**Alerts**). The workflow keeps
  the report and adds its `rekor.mismatches` to the alert's message, at
  most 20 with the count of the rest, each naming the instance, the
  entry's ID, its log index and its digest. All are public; the report
  holds nothing secret.
- **Not guaranteed:** that production's search found every entry (only
  staging is scanned). Rekor indexes the key as submitted, so an entry
  made with an anchor key in another PEM form (CRLF line ends, no final
  newline) or inside a certificate (a self-signed one, say) isn't found
  by the search: production's check catches misuse through standard
  clients, not a thief avoiding it. Nor that the log shows others the
  tree it shows this monitor (a split view: v1 has no witnesses, and
  comparing checkpoints from a second vantage point is future work); nor
  anything about a stolen anchor key used in another log, or not logged
  at all. Such a bundle fails the site's trusted root, but could pass
  for someone who trusts another. Rekor v2 holds no `hashedrekord` 0.0.1
  and has no search: if v1 freezes or the profile moves to v2, this
  check is redesigned.

## Changes

- **0.2.12 (2026-11-04), draft:** `votesctl check -all -rekor` (§7)
  searches Rekor v1 by each listed anchor key (production's check,
  the owner's choice a2 of 2026-11-05), verifies each entry (any other kind or digest
  under an anchor key is `unverified`), and makes an unknown digest a
  mismatch unless it is acknowledged, by PR, in
  `monitor/rekor-acknowledged-<env>.json`; a digest anchored again more
  than 24 hours later is a warning; on staging it also scans the log for
  every entry carrying an anchor key's SPKI and makes one the search
  missed a mismatch (`index gap`); it checks the log's checkpoint, and
  the newest bundle's, for consistency with the one recorded in an SSM
  parameter, the monitor's first state, created holding a sentinel that
  is a mismatch until an owner-run `-rekor-bootstrap`; a changed shard
  is a mismatch until an owner-run `-rekor-accept-shard`; verified
  entries are kept in an S3 object in a monitor bucket the stack adds;
  a search that fails 3 runs in a row, or is gone, is a mismatch, and
  fewer don't fail the run; requests are paced and capped, and a run cut
  short by the cap is `incomplete`; the check reads with a read-only
  session and a separate step writes the state back; the alert names
  each Rekor mismatch's entry.

- **0.2.11 (2026-11-04):** `votesctl check` is a monitor (§7): `ok` is
  false for a listing difference or a partial upload past 10 minutes,
  or an anchor whose RFC 3161 and Rekor times differ by over 10 minutes;
  `-all` walks the service list's kept versions and checks every
  proposal listed; permanent partial uploads can be acknowledged, by PR,
  in `monitor/acknowledged-<env>.json`, each entry naming the partial's
  served objects by key and SHA-256, which must be exactly those served
  (the report's `partial_objects` lists them); a signature alone gets
  the same 10 minutes' grace, from its `Last-Modified`; network fetches
  are retried; documented exit codes; a scheduled workflow runs it
  hourly on staging and production, publishes a failed run to an SNS
  topic through a role it assumes by GitHub OIDC, and puts a heartbeat
  whose alarm, after 3 hours without one, notifies the same topic (the
  stack's `alarmTopicArn` and `githubOidcProviderArn`). The trusted root is embedded in the
  build and refreshed through TUF at most once a day, the fetch made
  outside the lock so other checks go on with the root in use; a start that
  can't reach TUF runs on the embedded root if it is at most 90 days old
  (§4 item 4).
- **0.2.10 (2026-11-04):** the results' embedded signatures of the
  proposal and each extension must be the published `.sig` files byte
  for byte (§4 item 5), or the upload is refused with `sig_mismatch`;
  `votesctl check` fails such a vote, naming the document.
- **0.2.9 (2026-11-04):** the limits are as deployed: the stage throttle
  (the whole stage, 10/s, burst 20) and an AWS WAF per-address rate rule
  on `/api/` (100 requests in 5 minutes, on the decoded and normalized
  path, answered `429`), now in the stack; the service
  list is the operator's, published with `votesctl publish-services`,
  not a file in this repository.

- **0.2.8 (2026-11-02):** the results always set the index's close in
  force and extension count (never lower than stored), and an extension
  sets them from the published extensions, so a re-upload of an earlier
  extension moves neither backwards; a cached `404` for an extension
  means none yet.
- **0.2.7 (2026-11-02):** an upload whose document was written answers
  `201` even if the index update failed, with `"index_updated": false`
  in the body (it was `503`, so the publisher could not tell whether the
  document existed); an identical re-upload answers `200` and finishes
  the index, and an extension or the results add a missing index entry.
- **0.2.6 (2026-10-31):** the function keeps the service list it checked
  last and checks it again only when the list or its signature changes;
  both are still read on every upload, so a new list counts at once.
- **0.2.5 (2026-10-31):** the bucket policy keeps the service list's
  versions, `services/<version>.json` and `.sig`, write-once and never
  deleted, as it already did for the proposals' documents (§2), with a
  recovery deploy for a stray object at a version's key.
- **0.2.4 (2026-10-31):** `services.json` and its `.sig` are cached for
  10 seconds, not 5 minutes, as `votesctl publish-services` writes them:
  a list and a signature from different versions fail to verify until
  both caches have expired.
- **0.2.3 (2026-10-30):** every version of the service list is kept,
  write-once, as `services/<version>.json` and `.sig`, so a member vault
  that missed versions can catch up through the chain.
- **0.2.2 (2026-10-30):** follows BALLOT-PROTOCOL 0.11.0: the results'
  counts have `unhandled`, which the upload API requires (a results
  document without it is refused as `bad_document`).
- **0.2.1 (2026-10-29):** the code's rules: bundles are checked with
  Sigstore's own verifier and held to the profile; a proposal may be
  published until its close; extensions not after their close or the
  results; results a minute after the close and anchored after it;
  write order and leftovers; size caps.
- **0.2.0 (2026-10-29):** follows BALLOT-PROTOCOL 0.10.0: results in two
  parts, and the service list signed by the site's key. Pools, rosters,
  closings, mix lists, the Rekor monitor, mirrors, OpenTimestamps and
  reports are gone. The service list is signed and anchored.
- **0.1.0 (2026-10-29):** first draft.
