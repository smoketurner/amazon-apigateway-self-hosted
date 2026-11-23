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

# With --domain-cert-source acm the domain container serves the certificate
# API Gateway serves, so both must present the same leaf.
certificates_differ=0
if [[ "$(jq -r .domain_cert_source <<<"$ecs")" == "acm" ]]; then
  fingerprint() {
    # An unreachable gateway prints nothing, reported below, instead of ending the script.
    { openssl s_client -connect "$1" -servername "$2" </dev/null 2>/dev/null |
      openssl x509 -noout -fingerprint -sha256 2>/dev/null; } || true
  }
  host="$(jq -r .domain.base_url "$work/outputs.json" | sed -E 's|^https://||; s|/.*$||')"
  aws_print="$(fingerprint "$host:443" "$host")"
  apigw_print="$(fingerprint "$ip:8445" "$host")"
  if [[ -z "$aws_print" || "$aws_print" != "$apigw_print" ]]; then
    echo "the domain certificate differs: API Gateway ${aws_print:-none}, apigw ${apigw_print:-none}"
    certificates_differ=1
  else
    echo "apigw serves the same ACM certificate as API Gateway ($aws_print)"
  fi
fi

if [[ -s "$drift" ]]; then
  echo "apigw answered $(grep -c '^### ' "$drift") case(s) differently: $drift"
  exit 1
fi
if ((certificates_differ)); then
  exit 1
fi
echo "apigw on ECS matches API Gateway on every custom domain case"
