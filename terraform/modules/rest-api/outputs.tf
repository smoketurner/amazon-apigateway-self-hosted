output "api_id" {
  description = "ID of the reference REST API."
  value       = aws_api_gateway_rest_api.this.id
}

output "stage_name" {
  description = "Stage the API is deployed to."
  value       = aws_api_gateway_stage.this.stage_name
}

output "base_url" {
  description = "Invoke URL of the stage."
  value       = aws_api_gateway_stage.this.invoke_url
}

output "api_key_value" {
  description = "Value of the usage-plan API key for the /keyed route."
  value       = aws_api_gateway_api_key.this.value
  sensitive   = true
}
