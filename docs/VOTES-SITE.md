# votes.vettid.org

**Status:** 0.2.9 (2026-11-04), draft. The protocol this site serves is
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
   instance (staging or production, fetched through its TUF repository):
   the ECDSA signature over the document under one of the service's
   listed anchor keys, the Rekor entry and its inclusion proof, and one
   RFC 3161 timestamp.
5. **Order and fields:**
   - a proposal: anchored, and uploaded, before its `closes_at`; the
     same proposal again is accepted at any time (a retry);
   - an extension: `n` is the next number, it is anchored and uploaded
     before the `closes_at` it extends, never once results are
     published, and the total is within 24 h;
   - results: uploaded and anchored at least a minute after the final
     `closes_at`, when collection ends (BALLOT-PROTOCOL §7); they pass the observer's check (BALLOT-
     PROTOCOL §8.4) and contain the published proposal and extensions
     byte for byte, and `rows` hashes to their `rows_hash`.
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
`/api/`, beyond which that address's requests there are blocked (`403`)
until its rate falls below the limit. Everything else is allowed. The
ACL keeps CloudWatch metrics only: request sampling is off, so it keeps
no source addresses (§5).

## 5. What the site keeps about readers

Nothing. CloudFront access logs are off. The WAF counts requests per
address only for its rate rule's window, with no logging and no request
sampling. API Gateway access logs carry the route, status, size and
latency, never the source address. The function logs ids, types, sizes
and error codes.

## 6. Deployment

- The domain: an ACM certificate and an alias record in the vettid.org
  hosted zone, which the vettid.org stacks own.
- Deploys need the owner's go, as for the service vault and
  member-service.

## Changes

- **0.2.9 (2026-11-04):** the limits are as deployed: the stage throttle
  (the whole stage, 10/s, burst 20) and an AWS WAF per-address rate rule
  on `/api/` (100 requests in 5 minutes), now in the stack; the service
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
