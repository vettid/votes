# votes.vettid.org

**Status:** 0.2.12 (2026-11-10), draft. The protocol this site serves is
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
  is false (mismatches). A Rekor request that gets no answer
  (`rekor.error`, **The Rekor check**, "Rekor unavailable") is neither a
  failed check nor a mismatch until `failures` reaches 3: alone, it
  leaves `0`, and the heartbeat is put. An answer that arrives but is
  malformed or doesn't verify is a mismatch at once.
- **Alerts:** a stack deployed with `alarmTopicArn` (an SNS topic in the
  stack's region, `us-east-1`) and `githubOidcProviderArn` (the account's
  existing OIDC provider for `token.actions.githubusercontent.com`; the
  stack takes it, as an account has one, and makes none) has a role,
  `vettid-votes-<env>-monitor` (output `MonitorRoleArn`). Only GitHub's
  OIDC tokens with audience `sts.amazonaws.com`, subject
  `repo:vettid@168311946/votes@1438447065:ref:refs/heads/main` (the
  repository uses GitHub's immutable subjects, with the owner's and the
  repository's ids), or (0.2.12, for the owner-run Rekor jobs, **The
  Rekor check**) `…:environment:monitor-<env>-admin` for its own
  environment, and `job_workflow_ref`
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

**The Rekor check** (`-rekor`; the choices marked below are the
owner's (a) of 2026-11-05) looks in Rekor for anchors the site doesn't
show. `-rekor` without `-all`, or with `-since`, is a usage error (the
older proposals' digests would be left out). The profile's
`hashedrekord` 0.0.1 entries (§4) are only in Rekor v1:
`rekor.sigstore.dev` for production and `rekor.sigstage.dev` for
staging, as `-sigstore`. The `monitor` workflow runs it hourly with the
rest. The anchor keys are every key in every service's `anchor_keys` on
the current list (the list keeps past ones), each compared by its
SubjectPublicKeyInfo (SPKI, DER), never by PEM bytes. An entry is named
by its entry ID, 80 lowercase hex digits (the tree ID's 16 and the leaf
hash's 64), and matched by its last 64, which stay the same whichever
tree ID Rekor prefixes; every list and store below keeps the 80 and
matches the 64. The report's `rekor` holds the checkpoint, the counts,
each entry reported (`unknown`, `pending`, `acknowledged`), `warnings`,
`error`, `failures` and `mismatches`.

- **What it reads, and how:** only Rekor's `GET /api/v1/log`, `GET
  /api/v1/log/proof`, `POST /api/v1/index/retrieve` and `POST
  /api/v1/log/entries/retrieve`, from an allowlist in the client that
  refuses any other path or method (so it can never call
  `/api/v1/log/entries`, which adds to the log); and from the site only
  `GET` and `HEAD`. Both are tested. Answers come over TLS checked
  against the runner's system roots, which authenticates the server but
  not what it says: everything used is verified as below.
- **Two kinds of failure:** a request that doesn't get an answer (a
  network error, or a `429` or `5xx` still failing after the retries,
  **Pacing**) is `rekor.error` and counts toward **Rekor unavailable**.
  An answer that arrives and is malformed, is another `4xx`, or doesn't
  verify (a signature, a signed entry timestamp, an inclusion or
  consistency proof, an entry's body, a checkpoint's origin) is a
  mismatch at once, whatever the endpoint, and never counts as
  unavailable. A `404`, `410` or `501` from an endpoint the check needs
  (the search is gone in Rekor v2) is the mismatch `rekor: search
  unavailable` at once.
- **The log's keys:** each checkpoint and entry is verified under the
  Rekor key, at the instance's host, of the trusted root `votesctl
  check` runs on (§4 item 4: fetched through the instance's TUF
  repository, or the embedded one) that its key hint or `logID` names,
  valid at its time: an entry's integrated time; the run's time for the
  active shard's checkpoint; for an inactive shard's checkpoint, the
  integrated time of the entry it proves. A new log key so reaches the
  check through TUF, or the embedded root's update by PR (`site/roots/`).
  An entry or checkpoint under a key in neither is `unverified`; the
  active checkpoint's is one mismatch for the run, which then checks no
  consistency and no entry against it.
- **The checkpoint:** the active shard's signed checkpoint (`GET
  /api/v1/log`: origin, tree ID, tree size and root hash), verified
  under its key; its origin must be `<host> - <tree ID>`, and one that
  isn't is `rekor: inconsistent`. If the state (below) holds one of the
  same tree ID, a consistency proof from it (`GET /api/v1/log/proof`)
  must verify. A smaller tree, another root at the same size, or a proof
  that fails, all with the same tree ID, is `rekor: inconsistent`, and
  the recorded checkpoint is kept, so every later run reports it too,
  until the owner clears it (**Clearing**); a consistent one replaces
  it. The run also proves consistency from the newest published
  bundle's checkpoint (its inclusion proof's, in its own shard), which
  needs no state, so a state rolled back or reset can't take the check
  below it. An inclusion proof at a tree size larger than the run's
  checkpoint (a later entry) needs one consistency proof from the run's
  checkpoint to that size, fetched once per size and run, and counted
  against the cap. v1 checkpoints have no witness cosignatures, so this
  shows only that the log never contradicts what this monitor and the
  site's bundles saw before.
- **Freshness:** a checkpoint of the recorded tree ID whose tree size
  hasn't grown since the recorded one, two runs in a row (`stale_runs`
  in the state), is a mismatch, `rekor: stale`: a log that stops
  growing, or serves this monitor an old view, is reported, not trusted.
  `stale_runs` counts within one tree ID and is reset by a shard change
  or its acceptance. Staging gains about 600 entries an hour, production
  hundreds of thousands.
- **Shards:** a tree ID other than the state's is its own mismatch,
  `rekor: shard changed`, on every run until the owner accepts it
  (**Clearing**). Meanwhile the run still searches, verifies entries
  (each under its own proof's checkpoint and key) and compares digests;
  only the consistency from the state and staging's scan are withheld.
  Acceptance (`-rekor-accept-shard <tree ID>`) requires the recorded
  tree among `GET /api/v1/log`'s `inactiveShards`, its checkpoint
  consistent with that shard's final one, and then records the new
  shard's checkpoint; on staging the scan then reads the old shard's
  tail, from `scanned_to` to its final size, and the new shard from 0.
  An entry in an inactive shard is verified against that shard's
  checkpoint and tree, with `treeID` passed to `/api/v1/log/proof`. A
  global log index is the index within its shard plus the sizes of the
  shards before it (`inactiveShards`; all of them for the active
  shard), and an entry whose global and shard indexes don't map so is
  `unverified`.
- **The search** (production's check, **the owner's choice**, a2 of
  2026-11-05; the alternatives are a full scan, as staging's, of millions
  of entries a day, or no check of production, staging's alone): for
  each anchor key, `POST /api/v1/index/retrieve`
  `{"publicKey":{"format":"x509","content":"<base64 PEM>"}}`. Rekor
  marks it deprecated and best-effort: its results may be incomplete.
  As of Rekor v1.5.3 (checked in its source), the index is written from
  the canonicalized entry (`pkg/api/entries.go`; the hashedrekord
  type's `Canonicalize` replaces the submitted object before
  `IndexKeys`), under the `sha256` of the key's canonical PEM: a key in
  another PEM form (CRLF line ends, no final newline) is indexed as the
  same key. A key inside a certificate is not: its canonical value is
  the certificate's PEM (`pkg/pki/x509`, `CanonicalValue`), indexed
  under its hash and subjects, which a search by key doesn't match.
  What the search can miss is in **Not guaranteed**.
- **The canary** (both instances): every published bundle's own Rekor
  entry (its entry ID, from the bundle's log index and body) must be
  among its key's search results. One that isn't, its bundle integrated
  more than `ListingGrace` before the search, is a mismatch, `rekor:
  index gap`: a search that has stopped returning what it holds would
  otherwise pass silently on production, where nothing else checks the
  index.
- **Each entry found** is fetched (`POST /api/v1/log/entries/retrieve`,
  10 entry IDs a request) unless the verified store (below) holds it,
  and verified before its digest is used:
  - the entry ID's leaf hash is its body's;
  - the body is a `hashedrekord` 0.0.1 entry over a `sha256` digest
    naming an anchor key;
  - its ECDSA signature over the digest verifies under that key;
  - its signed entry timestamp and inclusion proof verify under the log's
    key, and the proof's checkpoint is the run's or consistent with it
    (its shard's, for an inactive shard);
  - its integrated time is not after the time it is verified plus 60
    seconds (clock skew).

  One under an anchor key that passes the log's checks (its leaf hash,
  signed entry timestamp, inclusion proof and index mapping) but is
  anything else (another kind or version, a `sha384` or `sha512`
  digest, a signature that doesn't verify) is a mismatch, `rekor: wrong
  kind`, whatever its digest. One that fails any of the log's checks is
  `rekor: unverified`: the answer can't be trusted to be the log's.
- **Digests:** a verified entry's digest is the `sha256` of a document's
  bytes, never of its `.sig`. Those known are the run's: each proposal's,
  extension's and results' `hashes`, the documents a partial upload's
  bundle anchors (already reported as `partial`), and the served
  document bytes of each acknowledged partial upload (its
  `partial_objects`). A digest no known document's is a mismatch,
  `rekor: unknown digest`; one that is a service-list version's or a
  results' `rows` is `rekor: unexpected digest` (the anchor key never
  signs those; the site key signs the list). An entry integrated less
  than `ListingGrace` (10 minutes) before the time it is verified, or up
  to the 60 seconds of skew after it (−60 s ≤ verified − integrated <
  10 min), is `pending`, not a mismatch, as its upload may not be done,
  so an anchor made during the run doesn't alarm. When the run's `lists` have an error (an index or archive month
  unread), its unknown and unexpected digests are reported with
  `lists_incomplete`: the run already exits `1`, and they are checked
  again by the next run that reads every list.
- **Anchored again:** a known digest may be anchored more than once (a
  retried upload). An entry for one integrated more than 24 hours after
  the digest's reference time is a mismatch, `rekor: anchored again`,
  named in the alert: the anchor key is in use. The reference time is the
  published bundle's integrated time, or, for a digest with no published
  bundle (an acknowledged partial upload's), the earliest verified
  entry's.
- **Staging's scan:** on staging only, the check also reads every entry
  of the active shard from `scanned_to` (an index within that shard,
  recorded with its tree ID) to the run's tree size, 10 by log index a
  request (about 600 entries an hour, so some 60 requests a run). It
  keeps every entry, of any kind, whose key or certificate carries an
  anchor key's SPKI (compared as SPKI, never as PEM bytes), each verified
  in full, as above (leaf hash, inclusion against the run's checkpoint,
  index mapping), and compared as above. An entry whose body doesn't
  parse is a warning (`rekor.warnings`), not a mismatch, as nothing in it
  can be read as an anchor key's: the report counts them
  (`rekor.unparsed`), and the alert names the count whenever the run
  alerts. An anchor
  key's entry the search didn't return, though integrated more than
  `ListingGrace` before the search began, is a mismatch, `rekor: index
  gap` **(the owner's (a) of 2026-11-05: an alarm, not a warning)**: the
  search is production's only check, so a sign that it misses entries
  has to reach someone. Production gains millions of entries a day and
  is never scanned.
- **Rekor unavailable:** a request that gets no answer (**Two kinds of
  failure**) is `rekor.error` and adds one to `failures` in the state,
  which a run that gets every answer it asked for resets; a run cut
  short by the cap or the time limit (`incomplete`) neither adds nor
  resets. Below 3 it is neither a failed
  check nor a mismatch: the run exits `0` if the rest held, and puts the
  heartbeat. At 3 consecutive runs it is a mismatch, `rekor: search
  unavailable` **(the owner's (a) of 2026-11-05: 3, as the heartbeat
  alarm's 3 hours: an outage of an hour or two, within Rekor's 99.5%
  availability objective, passes, and one that lasts is raised as soon
  as a stopped monitor would be)**.
- **Pacing:** Rekor's rate limits are undocumented. Requests go one at
  a time, at least 250 ms apart, at most 1,000 an instance a run, within
  10 minutes an instance a run; a network error, a `429` or a `5xx` is
  retried after 1, 2, 4 and 8 seconds (longer if `Retry-After` says so,
  at most 60 seconds). The work goes in this order: the checkpoint and
  its proofs, the searches, the entries they found, the canary, then
  staging's scan with what is left. At the cap or the time limit the run
  stops: the scan resumes next run from where it stopped, and a search
  or fetch left undone is a mismatch, `rekor: incomplete` (an alarm, not
  `search unavailable`: it says the work outgrew the cap, not that
  Rekor is down).
- **The verified store:** each verified entry is kept by its 80-hex
  entry ID (matched on the last 64) with its whole answer (body,
  integrated time, log ID, log indexes, signed entry timestamp and
  inclusion proof with its signed checkpoint), never a digest alone. Its
  checkpoint is proved consistent with the run's once, when the entry is
  fetched; every later run verifies the stored entry again locally, with
  no fetch: the leaf hash and the body, the signature over the digest,
  the signed entry timestamp, the inclusion under the stored checkpoint,
  that checkpoint's signature, and that its size is at most the recorded
  tree size. Consistency carries over through the state's chain of
  consistent checkpoints, so no stored size needs a proof again. It is `-rekor-verified <file>`, between
  runs the S3 object `rekor-verified.json` in the monitor's bucket,
  `vettid-votes-<env>-monitor`, which the stack adds (private,
  versioned, its noncurrent versions kept 90 days, blocking public
  access, kept when the stack is deleted). Not SSM: it grows with the
  anchors, and a standard parameter's 4 KB holds a few entries. The
  monitor role may only `s3:GetObject` and `s3:PutObject` it. A missing
  object (the first run) is an empty store; one that doesn't parse is a
  failed check (exit `1`).
- **Acknowledged entries:** `monitor/rekor-acknowledged-staging.json`
  and `-prod.json` (passed with `-rekor-acknowledged <file>`), beside
  the partial uploads' lists, whose entries name a document and not a
  Rekor entry, are strict JSON arrays of entries

  ```json
  {"instance": "staging", "uuid": "<hex>", "log_index": 123,
   "sha256": "<hex>", "finding": "unknown digest", "reason": "<why>",
   "acknowledged_at": "YYYY-MM-DD"}
  ```

  with no other members. `instance` is `-sigstore`'s, `uuid` the entry's
  80-hex entry ID as Rekor gives it (lowercase), matched by its last 64,
  `log_index` its global log index, `sha256` its digest (64 lowercase
  hex digits, or empty for an entry whose body has none), and `finding`
  one of `unknown digest`, `unexpected digest`, `anchored again`,
  `index gap` and `wrong kind`; no `(uuid, finding)` twice. `unverified`
  is never acknowledged: an answer that fails the log's checks may be
  forged, and acknowledging one would silence a later forgery under the
  same ID. That finding for that entry is reported in `acknowledged`,
  and is not a mismatch; nothing else is covered. Each run checks every
  listed entry (from the verified store, or fetched by entry ID): one
  that isn't there (`entries/retrieve` leaves a missing ID out of its
  answer rather than answering `404`), whose log index or digest
  differs, or that isn't an anchor key's is a mismatch, so the list stays
  true. A finding not
  acknowledged repeats on every run. As with the other lists, each entry
  is added by a PR that gives its reason, the owner reviews it
  (`.github/CODEOWNERS` covers `monitor/`), and both start empty; the
  report's mismatches have each entry's fields to copy.
- **The state:** `-rekor-state <file>` is read at the start and
  rewritten at the end: JSON `{"v": 1, "origin": "<origin>", "tree_id":
  "<id>", "tree_size": n, "root_hash": "<hex>", "stale_runs": n,
  "failures": n, "scan_tree_id": "<id>", "scanned_to": n}` (the last two
  on staging only). Between runs it is the SSM parameter
  `/vettid/votes/<env>/monitor/rekor-state` (standard, well under its
  4 KB). SSM holds no empty value, so the stack creates it holding the
  sentinel `{"v":1,"bootstrap":true}`, and only if it is absent: a
  custom resource, whose role may only put that one parameter, puts it
  with `Overwrite: false` on create (ignoring `ParameterAlreadyExists`),
  does nothing on update and keeps it on delete, so no deploy rewrites
  the state. An empty, sentinel or unparseable state is a mismatch,
  `rekor: no state`, and a run without `-rekor-bootstrap` writes it back
  unchanged (the report gives an unparseable state's SHA-256). A run without the state (another branch, or the role unset)
  checks no consistency from it, counts no failures and says so
  (`rekor.state` `none`).
- **Clearing** (owner-run only): `workflow_dispatch` inputs, with an
  `env` input so that one dispatch touches one environment. A dispatch
  with an admin input runs a separate job, for that `env` alone, in a
  GitHub Environment `monitor-<env>-admin` whose required reviewer is
  the owner and whose deployment-branch policy allows only `main`; the
  hourly job and a dispatch without one stay outside any environment.
  The admin job takes the `monitor` concurrency group at job level, so
  it waits for its approval without holding the group, and the hourly
  runs (and the heartbeat) go on meanwhile. A job in an environment
  presents the OIDC subject
  `repo:vettid@168311946/votes@1438447065:environment:monitor-<env>-admin`
  (the repository's immutable subjects), so the role's trust policy
  allows that subject for its environment as well as the `main` one,
  each with the same `job_workflow_ref` condition (**Alerts**).
  - `rekor_bootstrap` passes `-rekor-bootstrap`, which records the
    checkpoint it finds and starts staging's scan at the current tree
    size. It refuses (exit `2`) a state that is neither empty, nor the
    sentinel, nor unparseable with the SHA-256 the dispatch names
    (`rekor_state_sha256`, from the report). The newest bundle's
    checkpoint still binds it.
  - `rekor_reset_store` passes `-rekor-reset-store`, which starts the
    verified store empty (for one that doesn't parse): every entry is
    fetched and verified again, and on staging the scan rewinds to the
    bootstrap's start, as the store held what it had kept.
  - `rekor_accept_shard` passes `-rekor-accept-shard <tree ID>`
    (**Shards**).
  - `rekor_reset_pin` passes `-rekor-reset-pin <tree size>:<root hash>`,
    naming the recorded checkpoint it replaces (so a reset made for one
    `inconsistent` can't clear another), after the owner has looked into
    it; the run records the current checkpoint, still bound by the newest
    bundle's.

  Every other finding is cleared by its cause going away or by an
  acknowledgment.
- **Reading and writing back:** a first step assumes the role for a
  read-only session, narrowed by an inline session policy to
  `ssm:GetParameter` and `s3:GetObject`, and reads the state and the
  verified store into files. The check step runs with no AWS
  credentials (they are unset), on those files. A separate step after
  it assumes the role again with the write permissions and puts both
  back, the store before the state, whenever the check step ran,
  whatever its exit code (`!cancelled()`); each file is written whole,
  to a temporary name then renamed, so a cut-short write leaves the old
  one. A write-back that fails fails the run, which alerts; the heartbeat
  is put only after the write-back succeeded. A run past the job's
  20-minute timeout is cancelled and writes nothing: the next starts
  from the state before it, and the heartbeat alarm covers a hang. The
  read, change and write aren't atomic: they rely on the workflow's
  `concurrency: monitor` group (`cancel-in-progress: false`), which runs
  one run at a time, each environment with its own parameter and object.
- **Alarms:** each `rekor:` mismatch makes `ok` false (exit 3), so the
  failed run's alert goes to the topic (**Alerts**). The workflow keeps
  the report and adds its `rekor.mismatches` to the alert's message, at
  most 20 with the count of the rest, each naming the instance, the
  finding, the entry's ID, its log index and its digest. All are public;
  the report holds nothing secret.
- **Not guaranteed:**
  - that production's search returns every entry (only staging is
    scanned). Rekor's index is written after the entry, asynchronously,
    and a failed write is only logged, so an entry can be missing from
    it; the index can also be incomplete after a rebuild; and its
    answers are not signed, so a server that omits an entry from a
    search isn't caught by verifying what it returned. The canary
    catches a search that has stopped returning what it holds, not one
    that leaves out a single entry. And an entry whose anchor key is
    inside a certificate (a self-signed one, say) is indexed under the
    certificate, not the key, so production's search doesn't find it:
    it catches misuse through standard clients, not a thief who wraps
    the key to avoid it. Such an entry anchors nothing for VettID's
    verifiers: the site's (sigstore-go's key comparison) and the member
    vaults' (`vms/votewire`, which takes only a `PUBLIC KEY` block)
    refuse a bundle whose key is in a certificate; it could pass only
    with another verifier. (Another PEM form of the bare key doesn't
    hide an entry: the index holds its canonical form.)
  - that the log shows others the tree it shows this monitor (a split
    view: v1 has no witnesses, and comparing checkpoints from a second
    vantage point is future work);
  - anything about a stolen anchor key used in another log, or not
    logged at all. Such a bundle fails the site's trusted root, but
    could pass for someone who trusts another.

  Rekor v2 holds no `hashedrekord` 0.0.1 and has no search: if v1 freezes
  or the profile moves to v2, this check is redesigned.

## Changes

- **0.2.12 (2026-11-10):** `votesctl check -all -rekor` (§7)
  reads Rekor v1 through an allowlist of four endpoints (never one that
  adds to the log), and the site by `GET` and `HEAD` only. It searches
  by each listed anchor key (production's check, the owner's choice a2
  of 2026-11-05; as of Rekor v1.5.3 the index holds keys in canonical
  form, so only a key inside a certificate, an index write that failed
  or an omitting server hides an entry), with a canary: every published
  bundle's own entry must be among its key's results (`index gap`). It
  verifies each entry in full under the trusted root's log key, by
  `logID`, against the run's checkpoint (any other kind or digest under
  an anchor key is `unverified`); an unknown digest, or a service list's
  or rows' under an anchor key, is a mismatch, and so is a digest
  anchored again more than 24 hours later; entries younger than 10
  minutes at verification are `pending`. Answers that arrive but don't
  verify are mismatches at once; only requests that get no answer count
  toward `search unavailable`, after 3 runs. On staging it also scans
  the log for every entry carrying an anchor key's SPKI (`index gap`).
  It checks the log's checkpoint, and the newest bundle's, for
  consistency with the one recorded in an SSM parameter, and one that
  stops growing for two runs is `stale`; a changed shard is a mismatch
  until accepted, though the rest goes on. Acknowledgments, by PR, name
  an entry and its finding (`unknown digest`, `unexpected digest`,
  `anchored again`, `index gap`, `wrong kind`), never an answer that
  fails the log's checks (`unverified`); bootstrap, shard
  acceptance, a reset of an `inconsistent` pin and a reset of the store
  are owner-run, per environment, behind a GitHub Environment the owner
  approves, whose OIDC subject the role also trusts.
  Verified entries are kept whole, in an S3 object, proved consistent
  once and verified again locally each run. Requests are paced, capped and time-limited (`incomplete`);
  the check step has no AWS credentials, a separate step writes the
  store then the state back, atomically, a failed write-back alerts,
  and the heartbeat follows it; the alert names each Rekor mismatch's
  entry and finding.
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
