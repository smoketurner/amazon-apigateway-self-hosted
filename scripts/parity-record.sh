#!/usr/bin/env bash
# Records every parity case against the deployed reference stack, writing fixtures and exports
# into parity/ so `git diff parity/` shows what changed. Cases whose compared fields drifted from
# the committed fixtures are listed in target/parity-drift.md. Needs credentials for the stack's
# account (AWS_PROFILE) and AWS_REGION, or the stack's region in the profile.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
env_dir="$root/terraform/environments/dev"
mkdir -p "$root/target"
work="$(mktemp -d "$root/target/parity-record.XXXXXX")"
mkdir -p "$work/exports"

terraform -chdir="$env_dir" output -json parity_runner >"$work/outputs.json"
stage="$(jq -r .stage "$work/outputs.json")"
extensions='{"extensions":"apigateway,authorizers"}'
for api in rest rest_policy; do
  aws apigateway get-export --rest-api-id "$(jq -r ".$api.api_id" "$work/outputs.json")" \
    --stage-name "$stage" --export-type oas30 --parameters "$extensions" \
    "$work/exports/$api.openapi.json" >/dev/null
done
aws apigatewayv2 export-api --api-id "$(jq -r .http.api_id "$work/outputs.json")" \
  --stage-name "$stage" --specification OAS30 --output-type JSON \
  "$work/exports/http.openapi.json" >/dev/null

PARITY_API_KEY="$(terraform -chdir="$env_dir" output -raw api_key_value)"
PARITY_COGNITO_PASSWORD="$(terraform -chdir="$env_dir" output -raw cognito_test_password)"
export PARITY_API_KEY PARITY_COGNITO_PASSWORD

drift="$root/target/parity-drift.md"
: >"$drift"
cargo build --quiet -p apigw-parity
"$root/target/debug/apigw-parity" record \
  --outputs "$work/outputs.json" --cases "$root/parity/cases" --out "$root/parity" \
  --export-dir "$work/exports" --baseline "$root/parity" --drift-report "$drift" \
  --secret-env PARITY_API_KEY --secret-env PARITY_COGNITO_PASSWORD

if [[ -s "$drift" ]]; then
  echo "drifted cases: $(grep -c '^### ' "$drift"), listed in $drift"
else
  echo "no drift from the committed fixtures"
fi
git -C "$root" status --short parity
