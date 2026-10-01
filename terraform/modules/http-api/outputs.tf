output "api_id" {
  description = "ID of the reference HTTP API."
  value       = aws_apigatewayv2_api.this.id
}

output "base_url" {
  description = "Invoke URL of the stage."
  value       = aws_apigatewayv2_stage.this.invoke_url
}
