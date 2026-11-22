#!/usr/bin/env bash
# Compares the reference APIs' AWS-service integrations with apigw on ECS, which replay cannot
# stand in for. Needs credentials for the stack's account (AWS_PROFILE) and the ECS gateway
# (enable_ecs_gateway, enable_ecs_gateway_http) reachable from this machine.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
env_dir="$root/terraform/environments/dev"
mkdir -p "$root/target"
outputs="$root/target/parity-live-outputs.json"

terraform -chdir="$env_dir" output -json parity_runner >"$outputs"
ecs="$(terraform -chdir="$env_dir" output -json ecs_gateway)"
ip="$("$root/scripts/ecs-gateway-ip.sh" "$(jq -r .cluster_name <<<"$ecs")" \
  "$(jq -r .service_name <<<"$ecs")")"

uv run --no-project --python 3 python -I "$root/scripts/parity-live.py" "$outputs" "$ip"
