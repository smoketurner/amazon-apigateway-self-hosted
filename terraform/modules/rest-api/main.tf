resource "aws_api_gateway_rest_api" "this" {
  name                         = local.name
  description                  = "REST API covering the in-scope features, used as the parity reference."
  body                         = jsonencode(local.openapi)
  api_key_source               = "HEADER"
  minimum_compression_size     = 1024
  disable_execute_api_endpoint = false

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id

  triggers = {
    redeployment = sha1(aws_api_gateway_rest_api.this.body)
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "access" {
  count = var.enable_logging ? 1 : 0

  name              = "/aws/apigateway/${local.name}/access"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "execution" {
  count = var.enable_logging ? 1 : 0

  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.this.id}/${var.stage_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_api_gateway_stage" "this" {
  rest_api_id           = aws_api_gateway_rest_api.this.id
  deployment_id         = aws_api_gateway_deployment.this.id
  stage_name            = var.stage_name
  cache_cluster_enabled = var.enable_cache_cluster
  cache_cluster_size    = var.enable_cache_cluster ? var.cache_cluster_size : null
  xray_tracing_enabled  = false
  variables             = var.stage_variables

  dynamic "access_log_settings" {
    for_each = var.enable_logging ? [1] : []

    content {
      destination_arn = aws_cloudwatch_log_group.access[0].arn
      format          = local.access_log_format
    }
  }

  depends_on = [aws_cloudwatch_log_group.execution]
}

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.this.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled        = true
    logging_level          = var.enable_logging ? "INFO" : "OFF"
    data_trace_enabled     = false
    throttling_rate_limit  = 100
    throttling_burst_limit = 50
  }
}

resource "aws_api_gateway_method_settings" "throttled" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.this.stage_name
  method_path = "throttled/GET"

  settings {
    throttling_rate_limit  = var.throttle_rate_limit
    throttling_burst_limit = var.throttle_burst_limit
  }

  depends_on = [aws_api_gateway_method_settings.all]
}

resource "aws_api_gateway_method_settings" "cached" {
  count = var.enable_cache_cluster ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.this.stage_name
  method_path = "cached/GET"

  settings {
    caching_enabled      = true
    cache_ttl_in_seconds = 60
  }

  depends_on = [aws_api_gateway_method_settings.all]
}

resource "aws_api_gateway_usage_plan" "this" {
  name = "${var.name_prefix}-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.this.id
    stage  = aws_api_gateway_stage.this.stage_name
  }

  quota_settings {
    limit  = 1000
    period = "DAY"
  }

  throttle_settings {
    burst_limit = 10
    rate_limit  = 5
  }
}

resource "aws_api_gateway_api_key" "this" {
  name    = "${var.name_prefix}-key"
  enabled = true
}

resource "aws_api_gateway_usage_plan_key" "this" {
  key_id        = aws_api_gateway_api_key.this.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.this.id
}
