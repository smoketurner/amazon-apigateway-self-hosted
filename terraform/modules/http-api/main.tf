resource "aws_apigatewayv2_api" "this" {
  name          = local.name
  description   = "HTTP API covering the in-scope features, used as the parity reference."
  protocol_type = "HTTP"
  body          = jsonencode(local.openapi)
}

resource "aws_cloudwatch_log_group" "access" {
  count = var.enable_logging ? 1 : 0

  name              = "/aws/apigateway/${local.name}/access"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "this" {
  api_id          = aws_apigatewayv2_api.this.id
  name            = var.stage_name
  auto_deploy     = true
  stage_variables = var.stage_variables

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
      destination_arn = aws_cloudwatch_log_group.access[0].arn
      format          = local.access_log_format
    }
  }
}
