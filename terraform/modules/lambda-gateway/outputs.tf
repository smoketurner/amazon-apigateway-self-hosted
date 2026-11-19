output "repository_url" {
  description = "ECR repository to push the Lambda image to."
  value       = aws_ecr_repository.this.repository_url
}

output "role_arn" {
  description = "Role the gateway's AWS calls are made as. Add it to the trust policy of each integration role the gateway assumes."
  value       = aws_iam_role.this.arn
}

output "function_url" {
  description = "URL of the gateway; null until an image tag is set."
  value       = local.deploy_function ? aws_lambda_function_url.this[0].function_url : null
}

output "log_group_name" {
  description = "Log group holding the gateway's logs."
  value       = aws_cloudwatch_log_group.this.name
}
