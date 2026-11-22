resource "aws_acm_certificate" "this" {
  domain_name               = local.api_domain
  subject_alternative_names = [local.mtls_domain]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# New names only (_<token>.api.parity...); allow_overwrite stays false so an
# existing record is never replaced.
resource "aws_route53_record" "validation" {
  for_each = {
    for option in aws_acm_certificate.this.domain_validation_options : option.domain_name => option
  }

  zone_id         = data.aws_route53_zone.this.zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 300
  allow_overwrite = false
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for record in aws_route53_record.validation : record.fqdn]
}

# The truststore and the client certificates parity cases present.
resource "tls_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem       = tls_private_key.ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = 24 * 365
  allowed_uses          = ["cert_signing", "crl_signing"]

  subject {
    common_name  = "${var.name_prefix} parity client CA"
    organization = "apigw parity"
  }
}

resource "tls_private_key" "client" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "client" {
  private_key_pem = tls_private_key.client.private_key_pem

  subject {
    common_name  = "parity-client"
    organization = "apigw parity"
  }
}

resource "tls_locally_signed_cert" "client" {
  cert_request_pem      = tls_cert_request.client.cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = 24 * 90
  allowed_uses          = ["digital_signature", "client_auth"]
}

# A client certificate from a CA the truststore does not hold.
resource "tls_private_key" "stranger" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "stranger" {
  private_key_pem       = tls_private_key.stranger.private_key_pem
  validity_period_hours = 24 * 90
  allowed_uses          = ["digital_signature", "client_auth"]

  subject {
    common_name  = "parity-stranger"
    organization = "apigw parity"
  }
}

resource "aws_s3_bucket" "truststore" {
  bucket_prefix = "${var.name_prefix}-truststore-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "truststore" {
  bucket = aws_s3_bucket.truststore.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "truststore" {
  bucket = aws_s3_bucket.truststore.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "truststore" {
  bucket  = aws_s3_bucket.truststore.id
  key     = local.truststore_key
  content = tls_self_signed_cert.ca.cert_pem

  depends_on = [aws_s3_bucket_versioning.truststore]
}

resource "aws_apigatewayv2_domain_name" "api" {
  domain_name = local.api_domain

  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.this.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}

resource "aws_apigatewayv2_domain_name" "mtls" {
  domain_name = local.mtls_domain

  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.this.certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  mutual_tls_authentication {
    truststore_uri     = "s3://${aws_s3_bucket.truststore.id}/${local.truststore_key}"
    truststore_version = aws_s3_object.truststore.version_id
  }
}

resource "aws_apigatewayv2_api_mapping" "rest" {
  api_id          = var.rest_api_id
  domain_name     = aws_apigatewayv2_domain_name.api.id
  stage           = var.stage_name
  api_mapping_key = "rest"
}

resource "aws_apigatewayv2_api_mapping" "rest_multi_level" {
  api_id          = var.rest_api_id
  domain_name     = aws_apigatewayv2_domain_name.api.id
  stage           = var.stage_name
  api_mapping_key = "v1/orders"
}

resource "aws_apigatewayv2_api_mapping" "http" {
  api_id          = var.http_api_id
  domain_name     = aws_apigatewayv2_domain_name.api.id
  stage           = var.stage_name
  api_mapping_key = "http"
}

resource "aws_apigatewayv2_api_mapping" "mtls" {
  api_id      = var.rest_api_id
  domain_name = aws_apigatewayv2_domain_name.mtls.id
  stage       = var.stage_name
}

resource "aws_route53_record" "api" {
  zone_id         = data.aws_route53_zone.this.zone_id
  name            = local.api_domain
  type            = "A"
  allow_overwrite = false

  alias {
    name                   = aws_apigatewayv2_domain_name.api.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.api.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "mtls" {
  zone_id         = data.aws_route53_zone.this.zone_id
  name            = local.mtls_domain
  type            = "A"
  allow_overwrite = false

  alias {
    name                   = aws_apigatewayv2_domain_name.mtls.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.mtls.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
