locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = var.region

  default_tags = {
    Project     = var.name_prefix
    Environment = "dev"
    ManagedBy   = "terraform"
    Purpose     = "apigw-parity-reference"
  }

  # Safe to publish; the secret is added separately for the APIs.
  public_stage_variables = {
    echo_host = module.lambda_backends.echo_host
  }

  stage_variables = merge(local.public_stage_variables, {
    echo_secret = module.lambda_backends.echo_shared_secret
  })

  vpc_link = var.enable_vpc_link ? {
    id       = module.vpc_link[0].vpc_link_id
    dns_name = module.vpc_link[0].nlb_dns_name
  } : null
}
