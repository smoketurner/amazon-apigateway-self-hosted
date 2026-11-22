#!/usr/bin/env bash
# Regenerates crates/apigw-regex/src/tables.rs, Java's Unicode block and script names, by
# running Tables.java in the same pinned JDK image as run.sh. Needs Docker; no network access.
set -euo pipefail

IMAGE="eclipse-temurin@sha256:4d06038800655fe1211760cd561de70ef2ed7a47f5d69255e9834414602b7026"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$repo/crates/apigw-regex/src/tables.rs"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 777 "$tmp"

docker run --rm --network none \
  --volume "$here:/oracle:ro" \
  --volume "$tmp:/out" \
  --workdir /oracle \
  "$IMAGE" \
  java --add-opens java.base/java.lang=ALL-UNNAMED -Dfile.encoding=UTF-8 Tables.java /out/tables.rs

mv "$tmp/tables.rs" "$out"
echo "wrote $out"
