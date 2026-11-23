#!/usr/bin/env bash
# Records the CreateSession requests the AWS credential helper signs and writes them as the
# fixtures aws-rolesanywhere-credentials is tested against. Needs Docker; the build fetches the
# helper, and the run itself has no network access.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${1:-$repo/crates/aws-rolesanywhere-credentials/tests/fixtures/signing-helper.json}"
tag="aws-rolesanywhere-oracle:local"

docker build --quiet --tag "$tag" "$here" >/dev/null

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 777 "$tmp"
docker run --rm --network none --volume "$tmp:/out" "$tag" /out/signing-helper.json

mkdir -p "$(dirname "$out")"
mv "$tmp/signing-helper.json" "$out"
echo "wrote $out"
