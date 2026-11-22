output "api_id" {
  description = "ID of the reference HTTP API."
  value       = aws_apigatewayv2_api.this.id
}

output "base_url" {
  description = "Invoke URL of the stage."
  value       = aws_apigatewayv2_stage.this.invoke_url
}

output "log_group_arns" {
  description = "Access log group of the stage; empty without logging."
  value       = aws_cloudwatch_log_group.access[*].arn
}
