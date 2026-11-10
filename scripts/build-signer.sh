#!/bin/sh
# Builds cmd/anchor-signer for one environment (provided.al2023, arm64) into
# <out>/bootstrap, with that environment's configuration compiled in from
# deploy/signer-<env>.conf (GC #7606 §1, #7638 items 4 and 5): the code
# signature then covers the configuration, and the function reads nothing
# it trusts from its environment. Reproducible (no VCS stamp, no build id,
# trimmed paths, the go.mod toolchain), so CI's hash and the owner's
# rebuild of the same commit match before the owner signs it.
set -eu
env=${1:?usage: build-signer.sh <env> <out-dir>}
out=${2:?usage: build-signer.sh <env> <out-dir>}
cd "$(dirname "$0")/.."
conf="deploy/signer-$env.conf"
if [ ! -f "$conf" ]; then
	echo "build-signer: no $conf (deploy/signer.conf.example says what goes in it)" >&2
	exit 1
fi
get() {
	v=$(sed -n "s/^$1=//p" "$conf")
	if [ -z "$v" ] || [ "$(printf '%s' "$v" | tr -d 'A-Za-z0-9:/._,+=-')" != "" ]; then
		echo "build-signer: $conf: $1 is empty or has characters it can't have" >&2
		exit 1
	fi
	printf '%s' "$v"
}
ld="-s -w -buildid="
for k in Region KeyAlias ClaimsTable JournalGroup JournalStream VotesBucket VotesAPI Sigstore SiteKey ServiceIKs; do
	ld="$ld -X main.compiled$k=$(get "$k")"
done
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags="$ld" -o "$out/bootstrap" ./cmd/anchor-signer
sha256sum "$out/bootstrap"
