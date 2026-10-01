output "user_pool_id" {
  description = "ID of the reference user pool."
  value       = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  description = "ARN of the reference user pool, for Cognito authorizers."
  value       = aws_cognito_user_pool.this.arn
}

output "client_id" {
  description = "App client ID, the JWT audience."
  value       = aws_cognito_user_pool_client.this.id
}

output "issuer" {
  description = "Token issuer URL, for JWT authorizers."
  value       = local.issuer
}

output "test_username" {
  description = "User name of the test user."
  value       = aws_cognito_user.test.username
}

output "test_password" {
  description = "Password of the test user; exchange it for tokens with USER_PASSWORD_AUTH."
  value       = random_password.test_user.result
  sensitive   = true
}
