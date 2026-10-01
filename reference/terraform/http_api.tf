locals {
  http_api_name = "${var.name_prefix}-http"

  http_openapi = yamldecode(templatefile("${path.module}/openapi/http.yaml.tftpl", {
    name                      = local.http_api_name
    echo_invocation_uri       = local.echo_invocation_uri
    authorizer_invocation_uri = local.authorizer_invocation_uri
    invoke_role_arn           = aws_iam_role.apigateway_invoke.arn
    cors_origin               = var.cors_allowed_origin
    cognito_issuer            = local.cognito_issuer
    cognito_client_id         = aws_cognito_user_pool_client.reference.id
  }))
}

resource "aws_apigatewayv2_api" "reference" {
  name          = local.http_api_name
  description   = "HTTP API covering the in-scope features, used as the parity reference."
  protocol_type = "HTTP"
  body          = jsonencode(local.http_openapi)
}

resource "aws_cloudwatch_log_group" "http_access" {
  count = var.enable_logging ? 1 : 0

  name              = "/aws/apigateway/${local.http_api_name}/access"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "reference" {
  api_id      = aws_apigatewayv2_api.reference.id
  name        = var.stage_name
  auto_deploy = true

  stage_variables = merge(local.stage_variables, {
    echo_secret = random_password.echo_shared_secret.result
  })

  default_route_settings {
    throttling_rate_limit  = 100
    throttling_burst_limit = 50
  }

  route_settings {
    route_key              = "GET /throttled"
    throttling_rate_limit  = var.throttle_rate_limit
    throttling_burst_limit = var.throttle_burst_limit
  }

  dynamic "access_log_settings" {
    for_each = var.enable_logging ? [1] : []

    content {
      destination_arn = aws_cloudwatch_log_group.http_access[0].arn
      format = jsonencode({
        requestId        = "$context.requestId"
        extendedRequest  = "$context.extendedRequestId"
        ip               = "$context.identity.sourceIp"
        requestTime      = "$context.requestTime"
        httpMethod       = "$context.httpMethod"
        routeKey         = "$context.routeKey"
        status           = "$context.status"
        protocol         = "$context.protocol"
        responseLength   = "$context.responseLength"
        errorMessage     = "$context.error.message"
        authorizerError  = "$context.authorizer.error"
        integrationError = "$context.integrationErrorMessage"
      })
    }
  }
}
