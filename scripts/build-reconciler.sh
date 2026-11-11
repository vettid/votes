#!/bin/sh
# Builds cmd/anchor-reconciler for one environment (provided.al2023, arm64)
# into <out>/bootstrap, with that environment's configuration compiled in:
# deploy/reconciler-<env>.conf, the signer function's released resource
# policy (deploy/signer-policy-<env>.json) and the acknowledged signs
# (monitor/acknowledged-signs-<env>.json). The code signature then covers
# all three, and the function reads nothing it trusts from its
# environment. Reproducible, as build-signer.sh: CI's hash and the owner's
# rebuild of the same commit match before the owner signs it.
set -eu
env=${1:?usage: build-reconciler.sh <env> <out-dir>}
out=${2:?usage: build-reconciler.sh <env> <out-dir>}
cd "$(dirname "$0")/.."
conf="deploy/reconciler-$env.conf"
policy="deploy/signer-policy-$env.json"
acks="monitor/acknowledged-signs-$env.json"
for f in "$conf" "$policy" "$acks"; do
	if [ ! -f "$f" ]; then
		echo "build-reconciler: no $f (deploy/reconciler.conf.example says what goes where)" >&2
		exit 1
	fi
done
get() {
	v=$(sed -n "s/^$1=//p" "$conf")
	if [ -z "$v" ] || [ "$(printf '%s' "$v" | tr -d 'A-Za-z0-9:/._,+=-')" != "" ]; then
		echo "build-reconciler: $conf: $1 is empty or has characters it can't have" >&2
		exit 1
	fi
	printf '%s' "$v"
}
ld="-s -w -buildid="
for k in Region KeyAlias KeyARN KeySPKISHA256 ClaimsTable TrailName JournalGroup JournalStream TrailGroup VotesBucket Sigstore SignerFunction SignerRole CodeSha256; do
	ld="$ld -X main.compiled$k=$(get "$k")"
done
# base64 without line breaks, on GNU and BSD alike; the files are checked
# out byte for byte (.gitattributes: -text), so the hash reproduces.
b64() { base64 < "$1" | tr -d '\n'; }
ld="$ld -X main.compiledPolicy=$(b64 "$policy") -X main.compiledAcknowledged=$(b64 "$acks")"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags="$ld" -o "$out/bootstrap" ./cmd/anchor-reconciler
sha256sum "$out/bootstrap"
