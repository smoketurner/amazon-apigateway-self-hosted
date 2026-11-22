#!/usr/bin/env bash
# Prints the public IP of an ECS gateway task running the service's current task definition.
# Waits for any rollout to finish first, so a comparison never reaches a task that is still
# starting or one that is being replaced.
#
# usage: ecs-gateway-ip.sh CLUSTER SERVICE
set -euo pipefail

cluster="$1"
service="$2"

aws ecs wait services-stable --cluster "$cluster" --services "$service"
definition="$(aws ecs describe-services --cluster "$cluster" --services "$service" \
  --query 'services[0].taskDefinition' --output text)"
tasks="$(aws ecs list-tasks --cluster "$cluster" --service-name "$service" \
  --desired-status RUNNING --query 'taskArns' --output text)"
# shellcheck disable=SC2086 # the task ARNs are separate arguments
eni="$(aws ecs describe-tasks --cluster "$cluster" --tasks $tasks \
  --query "tasks[?taskDefinitionArn=='$definition' && lastStatus=='RUNNING'] | [0].attachments[0].details[?name=='networkInterfaceId'].value | [0]" \
  --output text)"
if [[ -z "$eni" || "$eni" == "None" ]]; then
  echo "no running task of $definition in $cluster/$service" >&2
  exit 1
fi
aws ec2 describe-network-interfaces --network-interface-ids "$eni" \
  --query 'NetworkInterfaces[0].Association.PublicIp' --output text
