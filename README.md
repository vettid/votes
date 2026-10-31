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
§8.4), with the site's public key (in the member vaults' release config):

```sh
go build -o votesctl ./cmd/votesctl
./votesctl check -site-key <base64> <proposal_id>
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
exactly those the results list), the results against the rows and
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
lacks it, which isn't reported). A `listing` entry doesn't fail the
check: the lists are rewritten after each document, and may lag behind
an upload not finished. Only a 404 is taken as not published.
`-trusted-root <file>` uses a Sigstore trusted root file instead of
fetching it.

## Deployment

Deploys need the owner's go. The stack is `VotesSite-<envName>` in
`cdk/`, always in `us-east-1` (CloudFront's certificate must be there).
The deploying machine needs Node 22 and Go: the function is built at
synth by `scripts/build-api.sh`, the build CI hashes.

Every deploy passes, from `cdk/` after `npm ci`:
`-c envName=<staging|prod> -c hostName=<name> -c hostedZoneId=<id> -c zoneName=vettid.org -c sigstore=<staging|production>`,
where `sigstore` matches the service vaults' `SV_SIGSTORE` for that
environment. None has a default.

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
