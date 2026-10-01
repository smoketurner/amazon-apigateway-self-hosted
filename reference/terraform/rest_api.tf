locals {
  rest_api_name        = "${var.name_prefix}-rest"
  rest_policy_api_name = "${var.name_prefix}-rest-policy"

  rest_openapi = yamldecode(templatefile("${path.module}/openapi/rest.yaml.tftpl", {
    name                      = local.rest_api_name
    partition                 = local.partition
    region                    = var.region
    account_id                = local.account_id
    echo_invocation_uri       = local.echo_invocation_uri
    authorizer_invocation_uri = local.authorizer_invocation_uri
    invoke_role_arn           = aws_iam_role.apigateway_invoke.arn
    user_pool_arn             = aws_cognito_user_pool.reference.arn
    queue_name                = aws_sqs_queue.target.name
    table_name                = aws_dynamodb_table.target.name
    state_machine_arn         = aws_sfn_state_machine.target.arn
    event_bus_name            = aws_cloudwatch_event_bus.target.name
    cors_origin               = var.cors_allowed_origin
    enable_vpc_link           = var.enable_vpc_link
    vpc_link_id               = try(aws_api_gateway_vpc_link.reference[0].id, "")
    vpc_link_dns_name         = try(aws_lb.vpc_link[0].dns_name, "")
  }))

  rest_policy_document = {
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*"
      },
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*/GET/ip-denied"
        Condition = {
          IpAddress = { "aws:SourceIp" = ["0.0.0.0/0", "::/0"] }
        }
      },
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*/GET/ip-restricted"
        Condition = {
          NotIpAddress = { "aws:SourceIp" = var.policy_restricted_cidrs }
        }
      },
    ]
  }

  rest_policy_openapi = yamldecode(templatefile("${path.module}/openapi/rest-policy.yaml.tftpl", {
    name        = local.rest_policy_api_name
    policy_json = jsonencode(local.rest_policy_document)
  }))
}

resource "aws_api_gateway_rest_api" "reference" {
  name                         = local.rest_api_name
  description                  = "REST API covering the in-scope features, used as the parity reference."
  body                         = jsonencode(local.rest_openapi)
  api_key_source               = "HEADER"
  minimum_compression_size     = 1024
  disable_execute_api_endpoint = false

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_deployment" "reference" {
  rest_api_id = aws_api_gateway_rest_api.reference.id

  triggers = {
    redeployment = sha1(aws_api_gateway_rest_api.reference.body)
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "rest_access" {
  count = var.enable_logging ? 1 : 0

  name              = "/aws/apigateway/${local.rest_api_name}/access"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "rest_execution" {
  count = var.enable_logging ? 1 : 0

  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.reference.id}/${var.stage_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_api_gateway_stage" "reference" {
  rest_api_id           = aws_api_gateway_rest_api.reference.id
  deployment_id         = aws_api_gateway_deployment.reference.id
  stage_name            = var.stage_name
  cache_cluster_enabled = var.enable_cache_cluster
  cache_cluster_size    = var.enable_cache_cluster ? var.cache_cluster_size : null
  xray_tracing_enabled  = false

  variables = merge(local.stage_variables, {
    echo_secret = random_password.echo_shared_secret.result
  })

  dynamic "access_log_settings" {
    for_each = var.enable_logging ? [1] : []

    content {
      destination_arn = aws_cloudwatch_log_group.rest_access[0].arn
      format = jsonencode({
        requestId        = "$context.requestId"
        extendedRequest  = "$context.extendedRequestId"
        ip               = "$context.identity.sourceIp"
        requestTime      = "$context.requestTime"
        httpMethod       = "$context.httpMethod"
        resourcePath     = "$context.resourcePath"
        status           = "$context.status"
        protocol         = "$context.protocol"
        responseLength   = "$context.responseLength"
        errorMessage     = "$context.error.message"
        authorizerError  = "$context.authorizer.error"
        integrationError = "$context.integration.error"
      })
    }
  }

  depends_on = [aws_api_gateway_account.this, aws_cloudwatch_log_group.rest_execution]
}

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.reference.id
  stage_name  = aws_api_gateway_stage.reference.stage_name
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
  rest_api_id = aws_api_gateway_rest_api.reference.id
  stage_name  = aws_api_gateway_stage.reference.stage_name
  method_path = "throttled/GET"

  settings {
    throttling_rate_limit  = var.throttle_rate_limit
    throttling_burst_limit = var.throttle_burst_limit
  }

  depends_on = [aws_api_gateway_method_settings.all]
}

resource "aws_api_gateway_method_settings" "cached" {
  count = var.enable_cache_cluster ? 1 : 0

  rest_api_id = aws_api_gateway_rest_api.reference.id
  stage_name  = aws_api_gateway_stage.reference.stage_name
  method_path = "cached/GET"

  settings {
    caching_enabled      = true
    cache_ttl_in_seconds = 60
  }

  depends_on = [aws_api_gateway_method_settings.all]
}

resource "aws_api_gateway_usage_plan" "reference" {
  name = "${var.name_prefix}-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.reference.id
    stage  = aws_api_gateway_stage.reference.stage_name
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

resource "aws_api_gateway_api_key" "reference" {
  name    = "${var.name_prefix}-key"
  enabled = true
}

resource "aws_api_gateway_usage_plan_key" "reference" {
  key_id        = aws_api_gateway_api_key.reference.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.reference.id
}

resource "aws_api_gateway_rest_api" "policy" {
  name                         = local.rest_policy_api_name
  description                  = "REST API with a resource policy, kept apart so the policy cannot block the other reference routes."
  body                         = jsonencode(local.rest_policy_openapi)
  disable_execute_api_endpoint = false

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_deployment" "policy" {
  rest_api_id = aws_api_gateway_rest_api.policy.id

  triggers = {
    redeployment = sha1(aws_api_gateway_rest_api.policy.body)
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "policy" {
  rest_api_id   = aws_api_gateway_rest_api.policy.id
  deployment_id = aws_api_gateway_deployment.policy.id
  stage_name    = var.stage_name
}
