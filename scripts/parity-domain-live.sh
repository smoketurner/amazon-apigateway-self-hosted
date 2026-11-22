#!/usr/bin/env bash
# Records the custom domain and mutual TLS cases against apigw on ECS (the domain container on
# port 8445) instead of API Gateway, and lists every case that answers differently from the
# committed fixtures in target/parity-domain-drift.md. Replay cannot serve a custom domain
# offline, so this is how those cases are compared. Needs credentials for the stack's account.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
env_dir="$root/terraform/environments/dev"
mkdir -p "$root/target"
work="$(mktemp -d "$root/target/parity-domain-live.XXXXXX")"
mkdir -p "$work/cases"
cp "$root/parity/cases/domain.yaml" "$work/cases/"

terraform -chdir="$env_dir" output -json parity_runner >"$work/outputs.json"
terraform -chdir="$env_dir" output -json parity_client_certificates >"$work/client-certs.json"
ecs="$(terraform -chdir="$env_dir" output -json ecs_gateway)"
ip="$("$root/scripts/ecs-gateway-ip.sh" "$(jq -r .cluster_name <<<"$ecs")" \
  "$(jq -r .service_name <<<"$ecs")")"

resolve=()
for api in domain domain_mtls; do
  host="$(jq -r ".$api.base_url" "$work/outputs.json" | sed -E 's|^https://||; s|/.*$||')"
  resolve+=(--resolve "$host=$ip:8445")
done

drift="$root/target/parity-domain-drift.md"
: >"$drift"
cargo build --quiet -p apigw-parity
"$root/target/debug/apigw-parity" record \
  --outputs "$work/outputs.json" --cases "$work/cases" --out "$work/recorded" \
  --baseline "$root/parity" --drift-report "$drift" \
  --client-certs "$work/client-certs.json" --insecure "${resolve[@]}"

if [[ -s "$drift" ]]; then
  echo "apigw answered $(grep -c '^### ' "$drift") case(s) differently: $drift"
  exit 1
fi
echo "apigw on ECS matches API Gateway on every custom domain case"
