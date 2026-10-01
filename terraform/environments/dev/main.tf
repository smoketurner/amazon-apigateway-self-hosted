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

  name_prefix = var.name_prefix
  lambda_function_arns = [
    module.lambda_backends.echo_function_arn,
    module.lambda_backends.authorizer_function_arn,
  ]
  queue_arn         = module.service_targets.queue_arn
  table_arn         = module.service_targets.table_arn
  state_machine_arn = module.service_targets.state_machine_arn
  event_bus_arn     = module.service_targets.event_bus_arn
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
