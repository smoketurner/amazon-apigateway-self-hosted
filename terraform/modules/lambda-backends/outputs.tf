output "echo_function_arn" {
  description = "ARN of the echo function invoked by AWS_PROXY integrations."
  value       = aws_lambda_function.echo.arn
}

output "echo_invocation_uri" {
  description = "API Gateway integration URI for the echo function."
  value       = "${local.invocation_prefix}/${aws_lambda_function.echo.arn}/invocations"
}

output "authorizer_function_arn" {
  description = "ARN of the deterministic authorizer function."
  value       = aws_lambda_function.authorizer.arn
}

output "authorizer_invocation_uri" {
  description = "API Gateway authorizer URI for the authorizer function."
  value       = "${local.invocation_prefix}/${aws_lambda_function.authorizer.arn}/invocations"
}

output "echo_function_url" {
  description = "Function URL of the secret-guarded echo used as the HTTP backend."
  value       = aws_lambda_function_url.echo.function_url
}

output "echo_host" {
  description = "Host name of the echo function URL, for the echo_host stage variable."
  value       = local.echo_host
}

output "echo_shared_secret" {
  description = "Shared secret the echo function URL requires in the x-echo-secret header."
  value       = random_password.echo_shared_secret.result
  sensitive   = true
}
