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
    domain = var.custom_domain_zone == null ? null : {
      base_url = "https://${module.custom_domain[0].api_domain}"
    }
    domain_mtls = var.custom_domain_zone == null ? null : {
      base_url = "https://${module.custom_domain[0].mtls_domain}"
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

output "ecs_gateway" {
  description = "Where the ECS gateway runs and where to push its image; null unless enable_ecs_gateway is true."
  value = var.enable_ecs_gateway ? {
    repository_url = module.ecs_gateway[0].repository_url
    cluster_name   = module.ecs_gateway[0].cluster_name
    service_name   = module.ecs_gateway[0].service_name
    task_role_arn  = module.ecs_gateway[0].task_role_arn
    log_group_name = module.ecs_gateway[0].log_group_name
    ports          = module.ecs_gateway[0].ports
  } : null
}

output "lambda_gateway" {
  description = "Where the Lambda gateway runs and where to push its image; null unless enable_lambda_gateway is true."
  value = var.enable_lambda_gateway ? {
    repository_url = module.lambda_gateway[0].repository_url
    function_url   = module.lambda_gateway[0].function_url
    role_arn       = module.lambda_gateway[0].role_arn
    log_group_name = module.lambda_gateway[0].log_group_name
  } : null
}

output "parity_client_certificates" {
  description = "PEM client certificates and keys for the mutual TLS cases: trusted (chained to the truststore's CA) and stranger (from another CA)."
  sensitive   = true
  value = var.custom_domain_zone == null ? null : {
    trusted_cert  = module.custom_domain[0].client_cert_pem
    trusted_key   = module.custom_domain[0].client_key_pem
    stranger_cert = module.custom_domain[0].stranger_cert_pem
    stranger_key  = module.custom_domain[0].stranger_key_pem
  }
}
