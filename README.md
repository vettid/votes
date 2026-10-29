# votes.vettid.org

The public record of VettID votes. Every proposal, pool, extension and
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
operator's `votesctl` and the CDK stack (`cdk/`) are written; nothing is
deployed yet.

## Deployment

Deploys need the owner's go. The stack is `VotesSite-<envName>` in
`cdk/` (Node 22, Go on the deploying machine: the function is built at
synth for arm64):

1. **First deploy**, from `cdk/`:
   `npx cdk deploy -c envName=staging -c hostName=<name> -c hostedZoneId=<id> -c zoneName=vettid.org`.
   It makes the bucket, the function, the API, the certificate, the
   CloudFront distribution and the name's records, and the site key's
   secret (output `SiteKeySecret`). Uploads are refused until step 3.
2. **The site key:** `votesctl site-key -secret <SiteKeySecret>` prints
   its public key. It also goes in the member vaults' release config
   (BALLOT-PROTOCOL §3.3).
3. **Deploy again** with `-c siteKey=<that key>`.
4. **The service list:** add each service to `services.json` (its
   identity keys, and its anchor key and certificate from the service
   vault's `GET /v1/anchor-key`), then
   `votesctl publish-services -secret <SiteKeySecret> -bucket <BucketName> -in services.json`.
   A list that drops anything the published one had is refused.

Staging checks bundles against Sigstore's staging instance, `prod`
against production, matching the service vaults' `SV_SIGSTORE`.

## License

AGPL-3.0 (see [LICENSE](LICENSE)).
