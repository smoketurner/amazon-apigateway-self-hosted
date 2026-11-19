module "lambda_backends" {
  source = "../../modules/lambda-backends"

  name_prefix        = var.name_prefix
  function_runtime   = var.function_runtime
  log_retention_days = var.log_retention_days
}

module "service_targets" {
  source = "../../modules/service-targets"

  name_prefix        = var.name_prefix
  log_retention_days = var.log_retention_days
}

module "cognito" {
  source = "../../modules/cognito"

  name_prefix = var.name_prefix
}

module "integration_role" {
  source = "../../modules/integration-role"

  name_prefix          = var.name_prefix
  lambda_function_arns = local.lambda_function_arns
  queue_arn            = module.service_targets.queue_arn
  table_arn            = module.service_targets.table_arn
  state_machine_arn    = module.service_targets.state_machine_arn
  event_bus_arn        = module.service_targets.event_bus_arn

  trusted_principal_arns = local.gateway_role_arns
}

module "account_cloudwatch_role" {
  source = "../../modules/account-cloudwatch-role"
  count  = var.manage_account_cloudwatch_role ? 1 : 0

  name_prefix = var.name_prefix
}

module "vpc_link" {
  source = "../../modules/vpc-link"
  count  = var.enable_vpc_link ? 1 : 0

  name_prefix = var.name_prefix
  vpc_id      = var.vpc_id
  subnet_ids  = var.vpc_link_subnet_ids
  target_ips  = var.vpc_link_target_ips
}

module "rest_api" {
  source = "../../modules/rest-api"

  name_prefix               = var.name_prefix
  stage_name                = var.stage_name
  stage_variables           = local.stage_variables
  echo_invocation_uri       = module.lambda_backends.echo_invocation_uri
  authorizer_invocation_uri = module.lambda_backends.authorizer_invocation_uri
  invoke_role_arn           = module.integration_role.role_arn
  user_pool_arn             = module.cognito.user_pool_arn
  queue_name                = module.service_targets.queue_name
  table_name                = module.service_targets.table_name
  state_machine_arn         = module.service_targets.state_machine_arn
  event_bus_name            = module.service_targets.event_bus_name
  cors_allowed_origin       = var.cors_allowed_origin
  vpc_link                  = local.vpc_link
  enable_logging            = var.enable_logging
  log_retention_days        = var.log_retention_days
  enable_cache_cluster      = var.enable_cache_cluster
  cache_cluster_size        = var.cache_cluster_size
  throttle_rate_limit       = var.throttle_rate_limit
  throttle_burst_limit      = var.throttle_burst_limit

  # REST API logging needs the account-wide CloudWatch role in place first.
  depends_on = [module.account_cloudwatch_role]
}

module "rest_policy_api" {
  source = "../../modules/rest-policy-api"

  name_prefix      = var.name_prefix
  stage_name       = var.stage_name
  restricted_cidrs = var.policy_restricted_cidrs
}

module "http_api" {
  source = "../../modules/http-api"

  name_prefix               = var.name_prefix
  stage_name                = var.stage_name
  stage_variables           = local.stage_variables
  echo_invocation_uri       = module.lambda_backends.echo_invocation_uri
  authorizer_invocation_uri = module.lambda_backends.authorizer_invocation_uri
  invoke_role_arn           = module.integration_role.role_arn
  cognito_issuer            = module.cognito.issuer
  cognito_client_id         = module.cognito.client_id
  cors_allowed_origin       = var.cors_allowed_origin
  enable_logging            = var.enable_logging
  log_retention_days        = var.log_retention_days
  throttle_rate_limit       = var.throttle_rate_limit
  throttle_burst_limit      = var.throttle_burst_limit
}

# What apigw may do to mirror the reference REST API, whatever it runs on.
module "gateway_policy" {
  source = "../../modules/gateway-policy"
  count  = local.any_gateway ? 1 : 0

  api_kind             = "rest"
  api_id               = module.rest_api.api_id
  stage_name           = var.stage_name
  lambda_function_arns = local.lambda_function_arns
  assumable_role_arns  = [module.integration_role.role_arn]
}

# A public-subnet VPC for the ECS gateway, unless subnets are passed in.
module "ecs_network" {
  source = "../../modules/ecs-network"
  count  = local.create_ecs_network ? 1 : 0

  name_prefix        = var.name_prefix
  availability_zones = local.ecs_network_availability_zones
}

# apigw itself on ECS Fargate, mirroring the reference REST API, to test a
# build against the real thing.
module "ecs_gateway" {
  source = "../../modules/ecs-gateway"
  count  = var.enable_ecs_gateway ? 1 : 0

  name_prefix         = var.name_prefix
  vpc_id              = local.ecs_gateway_vpc_id
  subnet_ids          = local.ecs_gateway_subnet_ids
  allowed_cidrs       = var.ecs_gateway_allowed_cidrs
  api_kind            = "rest"
  api_id              = module.rest_api.api_id
  stage_name          = var.stage_name
  base_path           = local.gateway_base_path
  image_tag           = var.ecs_gateway_image_tag
  log_retention_days  = var.log_retention_days
  gateway_policy_json = module.gateway_policy[0].json
  additional_apis     = local.ecs_gateway_additional_apis
}

# What the ECS gateway's second container may do to mirror the HTTP API.
module "gateway_policy_http" {
  source = "../../modules/gateway-policy"
  count  = var.enable_ecs_gateway_http ? 1 : 0

  api_kind             = "http"
  api_id               = module.http_api.api_id
  stage_name           = var.stage_name
  lambda_function_arns = local.lambda_function_arns
  assumable_role_arns  = [module.integration_role.role_arn]
}

# apigw as a Lambda function behind a function URL, mirroring the same API.
module "lambda_gateway" {
  source = "../../modules/lambda-gateway"
  count  = var.enable_lambda_gateway ? 1 : 0

  name_prefix         = var.name_prefix
  api_kind            = "rest"
  api_id              = module.rest_api.api_id
  stage_name          = var.stage_name
  base_path           = local.gateway_base_path
  image_tag           = var.lambda_gateway_image_tag
  log_retention_days  = var.log_retention_days
  gateway_policy_json = module.gateway_policy[0].json
}

module "github_oidc" {
  source = "../../modules/github-oidc"

  name_prefix       = var.name_prefix
  repository        = var.github_repository
  subjects          = var.github_subjects
  oidc_provider_arn = var.github_oidc_provider_arn
  stage_name        = var.stage_name
  rest_api_ids      = [module.rest_api.api_id, module.rest_policy_api.api_id]
  http_api_ids      = [module.http_api.api_id]
}
