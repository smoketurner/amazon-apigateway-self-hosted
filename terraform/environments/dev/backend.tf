# Partial configuration: pass the bucket and key at init time with
# `terraform init -backend-config=backend.hcl` (see backend.hcl.example), so no
# account-specific names are committed.
terraform {
  backend "s3" {}
}
