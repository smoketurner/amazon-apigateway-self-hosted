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
cluster="$(terraform -chdir="$env_dir" output -json ecs_gateway | jq -r .cluster_name)"
task="$(aws ecs list-tasks --cluster "$cluster" --desired-status RUNNING \
  --query 'taskArns[0]' --output text)"
eni="$(aws ecs describe-tasks --cluster "$cluster" --tasks "$task" \
  --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" --output text)"
ip="$(aws ec2 describe-network-interfaces --network-interface-ids "$eni" \
  --query 'NetworkInterfaces[0].Association.PublicIp' --output text)"

uv run --no-project --python 3 python -I "$root/scripts/parity-live.py" "$outputs" "$ip"
