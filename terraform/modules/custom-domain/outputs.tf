output "api_domain" {
  description = "Custom domain with REST (rest, v1/orders) and HTTP (http) API mappings. Available once its mappings exist."
  value       = local.api_domain

  depends_on = [aws_apigatewayv2_api_mapping.rest, aws_apigatewayv2_api_mapping.rest_multi_level, aws_apigatewayv2_api_mapping.http, aws_route53_record.api]
}

output "mtls_domain" {
  description = "Custom domain that requires a client certificate from the parity CA, mapping the REST API at its root. Available once its mappings exist."
  value       = local.mtls_domain

  depends_on = [aws_apigatewayv2_api_mapping.mtls, aws_route53_record.mtls]
}

output "truststore_arn" {
  description = "S3 object holding the mutual TLS truststore."
  value       = "${aws_s3_bucket.truststore.arn}/${local.truststore_key}"
}

output "client_cert_pem" {
  description = "Client certificate chained to the truststore's CA."
  value       = tls_locally_signed_cert.client.cert_pem
}

output "client_key_pem" {
  description = "Key of the trusted client certificate."
  value       = tls_private_key.client.private_key_pem
  sensitive   = true
}

output "stranger_cert_pem" {
  description = "Client certificate from a CA the truststore does not hold."
  value       = tls_self_signed_cert.stranger.cert_pem
}

output "stranger_key_pem" {
  description = "Key of the untrusted client certificate."
  value       = tls_private_key.stranger.private_key_pem
  sensitive   = true
}
