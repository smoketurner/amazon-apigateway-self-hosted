#!/usr/bin/env bash
# Renders every case file in cases/ with Apache Velocity 1.7 and Jayway JsonPath in a pinned JDK
# image and writes the results next to it as <name>.expected.jsonl. Needs Docker; the run itself
# has no network access.
#
# usage: run.sh [cases-dir]   (default: the cases/ directory next to this script)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cases="$(cd "${1:-$here/cases}" && pwd)"
tag="apigw-vtl-oracle:local"

docker build --quiet --tag "$tag" "$here" >/dev/null

for input in "$cases"/*.json; do
  name="$(basename "$input" .json)"
  [[ "$name" == "defaults" ]] && continue
  tmp="$(mktemp -d)"
  chmod 777 "$tmp"
  docker run --rm --network none \
    --volume "$cases:/work:ro" \
    --volume "$tmp:/out" \
    "$tag" /work/defaults.json "/work/$name.json" "/out/$name.expected.jsonl"
  mv "$tmp/$name.expected.jsonl" "$cases/$name.expected.jsonl"
  rmdir "$tmp"
  echo "wrote $cases/$name.expected.jsonl ($(wc -l <"$cases/$name.expected.jsonl" | tr -d ' ') cases)"
done
