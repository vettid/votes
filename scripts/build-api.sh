#!/bin/sh
# Builds cmd/votes-api for Lambda (provided.al2023, arm64) into $1/bootstrap.
# The CDK stack runs this at synth, and CI runs it and prints the hash, so
# the binary a deploy ships can be compared with CI's for the same commit:
# no VCS stamp, no build id, trimmed paths.
set -eu
out=${1:?usage: build-api.sh <dir>}
cd "$(dirname "$0")/.."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$out/bootstrap" ./cmd/votes-api
