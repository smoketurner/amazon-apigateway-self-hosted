#!/usr/bin/env bash
# Regenerates the java.util.regex fixtures by running Oracle.java in a pinned JDK image.
# Needs Docker; the container runs without network access.
set -euo pipefail

IMAGE="eclipse-temurin@sha256:4d06038800655fe1211760cd561de70ef2ed7a47f5d69255e9834414602b7026"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${1:-$repo/crates/apigw-regex/tests/fixtures/java-regex.jsonl}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 777 "$tmp"

docker run --rm --network none \
  --volume "$here:/oracle:ro" \
  --volume "$tmp:/out" \
  --workdir /oracle \
  "$IMAGE" \
  java -Dfile.encoding=UTF-8 Oracle.java cases.json /out/fixtures.jsonl

mkdir -p "$(dirname "$out")"
mv "$tmp/fixtures.jsonl" "$out"
echo "wrote $out ($(wc -l <"$out" | tr -d ' ') records)"
