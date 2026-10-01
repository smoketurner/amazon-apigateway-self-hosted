output "parity_runner" {
  description = "Everything apigw-parity needs, with no secrets. Save with: terraform output -json parity_runner > ../../../parity/outputs.json"
  value = {
    account_id = local.account_id
    partition  = local.partition
    region     = local.region
    stage      = var.stage_name
    rest = {
      api_id   = module.rest_api.api_id
      base_url = module.rest_api.base_url
    }
    rest_policy = {
      api_id   = module.rest_policy_api.api_id
      base_url = module.rest_policy_api.base_url
    }
    http = {
      api_id   = module.http_api.api_id
      base_url = module.http_api.base_url
    }
    stage_variables = local.public_stage_variables
    cognito = {
      user_pool_id = module.cognito.user_pool_id
      client_id    = module.cognito.client_id
      issuer       = module.cognito.issuer
      username     = module.cognito.test_username
    }
    vpc_link_enabled = var.enable_vpc_link
    cache_enabled    = var.enable_cache_cluster
  }
}

output "api_key_value" {
  description = "Value of the usage-plan API key for the /keyed route."
  value       = module.rest_api.api_key_value
  sensitive   = true
}

output "cognito_test_password" {
  description = "Password of the Cognito test user; exchange it for tokens with USER_PASSWORD_AUTH."
  value       = module.cognito.test_password
  sensitive   = true
}

output "echo_shared_secret" {
  description = "Shared secret the echo function URL requires in the x-echo-secret header."
  value       = module.lambda_backends.echo_shared_secret
  sensitive   = true
}

output "echo_function_url" {
  description = "Lambda function URL of the secret-guarded echo."
  value       = module.lambda_backends.echo_function_url
}

output "github_ci_role_arn" {
  description = "Role the parity workflow assumes through GitHub OIDC."
  value       = module.github_oidc.role_arn
}

output "target_resources" {
  description = "Names and ARNs of the service-integration targets."
  value = {
    sqs_queue_url     = module.service_targets.queue_url
    dynamodb_table    = module.service_targets.table_name
    state_machine_arn = module.service_targets.state_machine_arn
    event_bus_name    = module.service_targets.event_bus_name
    event_log_group   = module.service_targets.event_log_group
  }
}
