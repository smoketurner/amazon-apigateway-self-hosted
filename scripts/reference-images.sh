#!/usr/bin/env bash
# Builds the ECS and Lambda gateway images from the current commit, pushes them to the reference
# stack's ECR repositories, and points terraform.tfvars at them. Run `terraform apply` after.
# Needs credentials for the stack's account (AWS_PROFILE) with ECR push access.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
env_dir="$root/terraform/environments/dev"
tfvars="$env_dir/terraform.tfvars"
if [[ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]]; then
  echo "commit or stash your changes first: the image tag names the commit" >&2
  exit 1
fi
tag="eager-$(git -C "$root" rev-parse --short HEAD)"

ecs_repo="$(terraform -chdir="$env_dir" output -json ecs_gateway | jq -r .repository_url)"
lambda_repo="$(terraform -chdir="$env_dir" output -json lambda_gateway | jq -r .repository_url)"
aws ecr get-login-password | docker login --username AWS --password-stdin "${ecs_repo%%/*}"

# Lambda refuses an image index, so neither image carries a provenance attestation.
docker build --provenance=false --platform linux/arm64 -t apigw:local -t "$ecs_repo:$tag" "$root"
docker build --provenance=false --platform linux/arm64 --build-arg APIGW_IMAGE=apigw:local \
  -t "$lambda_repo:$tag" "$root/terraform/modules/lambda-gateway/image"
docker push "$ecs_repo:$tag"
docker push "$lambda_repo:$tag"

sed -i.bak -E \
  -e "s/^(ecs_gateway_image_tag[[:space:]]*=[[:space:]]*).*/\\1\"$tag\"/" \
  -e "s/^#?(lambda_gateway_image_tag[[:space:]]*=[[:space:]]*).*/\\1\"$tag\"/" \
  "$tfvars"
mv "$tfvars.bak" "$root/target/terraform.tfvars.bak"
terraform fmt "$tfvars" >/dev/null
grep -E '^(ecs|lambda)_gateway_image_tag' "$tfvars"
echo "pushed $tag; now: terraform -chdir=terraform/environments/dev apply"
