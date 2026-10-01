output "api_id" {
  description = "ID of the resource-policy REST API."
  value       = aws_api_gateway_rest_api.this.id
}

output "base_url" {
  description = "Invoke URL of the stage."
  value       = aws_api_gateway_stage.this.invoke_url
}
