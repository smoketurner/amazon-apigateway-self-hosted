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

  # The ECS gateway brings its own network unless it is given subnets.
  create_ecs_network             = var.enable_ecs_gateway && length(var.ecs_gateway_subnet_ids) == 0
  ecs_network_availability_zones = slice(data.aws_availability_zones.available.names, 0, 2)
  ecs_gateway_vpc_id             = local.create_ecs_network ? module.ecs_network[0].vpc_id : var.vpc_id
  ecs_gateway_subnet_ids         = local.create_ecs_network ? module.ecs_network[0].public_subnet_ids : var.ecs_gateway_subnet_ids

  any_gateway = var.enable_ecs_gateway || var.enable_lambda_gateway

  # The gateways serve the API under the stage name, as its execute-api URL
  # does, so `$context.path` and Lambda events match the real API's.
  gateway_base_path = "/${var.stage_name}"

  # Only the role outputs, not the whole modules: each gateway's definition
  # depends on the REST API, which depends on the integration role.
  gateway_role_arns = concat(
    var.enable_ecs_gateway ? [module.ecs_gateway[0].task_role_arn] : [],
    var.enable_lambda_gateway ? [module.lambda_gateway[0].role_arn] : [],
  )

  lambda_function_arns = [
    module.lambda_backends.echo_function_arn,
    module.lambda_backends.authorizer_function_arn,
  ]

  vpc_link = var.enable_vpc_link ? {
    id       = module.vpc_link[0].vpc_link_id
    dns_name = module.vpc_link[0].nlb_dns_name
  } : null
}
