# votes.vettid.org

**Status:** 0.1.0 (2026-10-29), draft. The protocol this site serves is
[BALLOT-PROTOCOL](https://github.com/vettid/service-vault/blob/main/docs/BALLOT-PROTOCOL.md)
(0.5.0); its §3.5 is this site's contract and §8.5 has the document
schemas. Where this document and §3.5 differ, §3.5 wins and this
document is corrected.

## 1. What it is for

- Members learn of proposals here, without the organisation's service.
- Every document of a vote (proposal, pools, extension, results) is
  here, the same for every reader, and never changes once published.
- Observers check a vote from here alone (BALLOT-PROTOCOL §8.4).

The site is run by VettID and is independent of every service vault. It
holds no keys that sign votes, no member data, and no sessions. It keeps
no record of who reads what.

**What it can't do:** alter a document, since the service's signature and
the Rekor anchor catch that. **What it could do:** withhold a document,
or show readers different indexes. BALLOT-PROTOCOL §3.5 and §8.3 limit
what that gains.

## 2. Architecture

| Part | What it is |
|---|---|
| Bucket | Private S3 bucket, versioned, blocking public access. Read only through CloudFront (origin access control). Writes only by the upload function. |
| CloudFront | `votes.vettid.org`. Serves `/v1/*` from the bucket and `/api/*` from the API. Security headers as vettid.org's sites. No access logs. |
| Upload API | API Gateway HTTP API → Lambda `votes-api` (Go, arm64). |
| Monitor | EventBridge schedule (every 5 minutes) → Lambda `votes-monitor` (Go): Rekor watch and OpenTimestamps upgrades. |
| Service list | `services.json` in this repository, changed only by PR, published at deploy. |
| Stack | CDK (TypeScript), `VotesSite-staging` and `VotesSite-prod`, as member-service. |

**(chosen; not in the spec:** Lambda rather than an ECS service as
member-service runs, because uploads are a few per vote. The function's
zip is built in CI with attested build provenance, like the images.)

**Write-once** is the bucket's conditional write: every document is put
with `If-None-Match: *`. A `412` means the path exists: the function
compares the bytes and answers `200` if they are equal and `409` if not.
The function's role cannot delete objects. Production adds Object Lock
retention (governance mode) on `v1/p/`, with a period for the owner to
set.

## 3. Paths

All under `https://votes.vettid.org/v1/`.

| Path | Contents | Cache |
|---|---|---|
| `services.json` | `[{service_id, name, ik}]`, with `service_id` the lower-case hex of `H(ik)[0:16]` | 5 min |
| `index.json` | Proposals open or closed within the last 30 days: `[{proposal_id, service_id, proposal_hash, binding, opens_at, closes_at, count_until, extended, published}]`, by `opens_at` | 60 s |
| `archive/<YYYY-MM>.json` | Every proposal by the month of `opens_at`, same entries | 60 s |
| `p/<proposal_id>/proposal.json`, `.sig`, `.sigstore.json` | The proposal, `proposal_sig` (raw 64 bytes), its anchor bundle | 1 year, immutable |
| `p/<proposal_id>/pool-<n>.hash`, `.sig`, `.sigstore.json` | Before `count_until`: the pool's hash (32 raw bytes), `pool_sig`, its anchor bundle | 1 year, immutable |
| `p/<proposal_id>/pool-<n>.json` | After `count_until`: the pool's bytes | 1 year, immutable |
| `p/<proposal_id>/extension.json`, `.sig`, `.sigstore.json` | An extension | 1 year, immutable |
| `p/<proposal_id>/results.json`, `.sig`, `.sigstore.json`, `.ots` | The results; the OpenTimestamps proof for binding votes, upgraded in place (§6) | 1 year (`.ots`: 1 h) |
| `p/<proposal_id>/alarms.json` | Monitor alarms (§5); absent when there are none | 60 s |
| `p/<proposal_id>/reports.json` | Report counts per flag, verified and unverified (§7) | 60 s |

## 4. Upload API

`POST https://votes.vettid.org/api/v1/p/<proposal_id>/<name>`, where
`<name>` is `proposal`, `pool-<n>`, `extension` or `results`. The body is
JSON:

| Field | |
|---|---|
| `doc` | `b64` of the document's bytes; for a pool before `count_until`, absent |
| `hash` | for a pool before `count_until`: `b64` of `pool_hash`; otherwise absent |
| `sig` | `b64` of the service's detached signature (BALLOT-PROTOCOL §3.1, §3.3, §4.4, §8.1) |
| `bundle` | the Sigstore bundle, as JSON |

There is no other credential: the service's signature is the
authentication.

**Checks, in order** (each failure is `422` with an error code):
1. **Service:** for a proposal, its `service` key is on the service
   list; for anything else, the proposal is already here.
2. **Bytes:** the document is canonical JCS and matches its schema
   (BALLOT-PROTOCOL §2, §8.5); its `proposal_id` is the path's.
3. **Signature:** under the proposal's `service` key, with the
   document's label.
4. **Anchor:** the bundle's `hashedrekord` entry has the document's
   hash, a valid ECDSA P-256 signature under the proposal's
   `anchor_key`, and an inclusion proof to a checkpoint signed by
   Rekor's key, pinned in the function's config.
5. **Order and fields:**
   - a proposal: `record_at ≤ now < opens_at`, and the times as §3.1
     requires;
   - a pool: `n` is the next `pool_seq`, and the proposal isn't past
     `closes_at`;
   - a pool's bytes: after `count_until`, and their hash is the
     published one;
   - an extension: at most one, before `closes_at`, and within §10.2's
     24-hour cap;
   - results: after `count_until`, and they contain the published
     proposal, pools and extension byte for byte.
6. **Write-once** (§2).

Then the function updates `index.json` and the archive with a
conditional write on their ETag, retrying on a conflict.

**Answers:** `201` published, `200` already published with the same
bytes, `409` a different document is published there, `422` a check
failed, `413` too large.

**Size:** a request is at most 6 MB (Lambda's limit), which holds the
results of about 7,000 ballots. Larger votes need a two-step upload
through the bucket; not in 0.1.0.

**Limits:** API Gateway throttling per route, and AWS WAF's rate rule on
`/api/*`.

## 5. Monitor

- **Rekor:** for each proposal with no results yet, or with results less
  than a day old, the monitor reads Rekor's new entries since its last
  checkpoint and looks for entries whose public key is the proposal's
  `anchor_key`. An entry that is not one of the proposal's published
  documents is an alarm, written to `alarms.json` with the entry's log
  index and hash. Its state (the last checkpoint read) is in the bucket.
  - **To measure before deploy:** the rate of Rekor's public log, and
    whether a 5-minute run keeps up with it. If not, the monitor runs
    as a scheduled ECS task.
- **OpenTimestamps:** for a binding vote, each document's hash is
  submitted to the public calendars when it is published, and the
  pending proof is upgraded daily until Bitcoin confirms it.

## 6. What the site keeps about readers

Nothing. CloudFront access logs are off. API Gateway access logs carry
the route, status, size and latency, never the source address. The
functions log ids, types, sizes and error codes.

## 7. Reports

`POST https://votes.vettid.org/api/v1/p/<proposal_id>/report`, after
`count_until` and within 30 days, from the member's app with no session
(BALLOT-PROTOCOL §10.2):

- **Body:** `{flags: [string], vk?: b64, cert_prefix?: b64, cert_sig?: b64, report_sig?: b64}`.
- **Flags:** `outage`, `certification_refused`, `proposal_refused`, and
  `check_<n>` for the failed BALLOT-PROTOCOL §8.3 check.
- **Verified** reports carry a voting key with its certificate, and
  `report_sig = Sign(vk, "vettid/vote/1/report" ‖ 0x00, proposal_hash ‖ flags)`
  (the label is to be added to BALLOT-PROTOCOL). One per `vk`: a second
  is refused.
- **Unverified** reports are counted apart.
- The site publishes only counts per flag, in `reports.json`.

## 8. Deployment

- The domain: an ACM certificate and an alias record in the vettid.org
  hosted zone, which the vettid.org stacks own.
- Deploys need the owner's go, as for the service vault and
  member-service.

## Changes

- **0.1.0 (2026-10-29):** first draft.
