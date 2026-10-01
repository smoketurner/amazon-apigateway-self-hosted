locals {
  execute_api_host = "execute-api.${var.region}.amazonaws.com"
}

output "parity_runner" {
  description = "Everything apigw-parity needs, with no secrets. Save with: terraform output -json parity_runner > parity/outputs.json"
  value = {
    region = var.region
    stage  = var.stage_name
    rest = {
      api_id   = aws_api_gateway_rest_api.reference.id
      base_url = "https://${aws_api_gateway_rest_api.reference.id}.${local.execute_api_host}/${var.stage_name}"
    }
    rest_policy = {
      api_id   = aws_api_gateway_rest_api.policy.id
      base_url = "https://${aws_api_gateway_rest_api.policy.id}.${local.execute_api_host}/${var.stage_name}"
    }
    http = {
      api_id   = aws_apigatewayv2_api.reference.id
      base_url = "https://${aws_apigatewayv2_api.reference.id}.${local.execute_api_host}/${var.stage_name}"
    }
    stage_variables = local.stage_variables
    cognito = {
      user_pool_id = aws_cognito_user_pool.reference.id
      client_id    = aws_cognito_user_pool_client.reference.id
      issuer       = local.cognito_issuer
      username     = aws_cognito_user.reference.username
    }
    vpc_link_enabled = var.enable_vpc_link
    cache_enabled    = var.enable_cache_cluster
  }
}

output "api_key_value" {
  description = "Value of the usage-plan API key for the /keyed route."
  value       = aws_api_gateway_api_key.reference.value
  sensitive   = true
}

output "cognito_test_password" {
  description = "Password of the Cognito test user; exchange it for tokens with USER_PASSWORD_AUTH."
  value       = random_password.cognito_user.result
  sensitive   = true
}

output "echo_shared_secret" {
  description = "Shared secret the echo function URL requires in the x-echo-secret header."
  value       = random_password.echo_shared_secret.result
  sensitive   = true
}

output "echo_function_url" {
  description = "Lambda function URL of the secret-guarded echo."
  value       = aws_lambda_function_url.echo.function_url
}

output "github_ci_role_arn" {
  description = "Role the parity workflow assumes through GitHub OIDC."
  value       = aws_iam_role.github_ci.arn
}

output "target_resources" {
  description = "Names and ARNs of the service-integration targets."
  value = {
    sqs_queue_url     = aws_sqs_queue.target.url
    dynamodb_table    = aws_dynamodb_table.target.name
    state_machine_arn = aws_sfn_state_machine.target.arn
    event_bus_name    = aws_cloudwatch_event_bus.target.name
    event_log_group   = aws_cloudwatch_log_group.events_catch_all.name
  }
}
