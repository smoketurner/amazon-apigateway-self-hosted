resource "aws_api_gateway_rest_api" "this" {
  name                         = local.name
  description                  = "REST API with a resource policy, kept apart so the policy cannot block the other reference routes."
  body                         = jsonencode(local.openapi)
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

resource "aws_api_gateway_stage" "this" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  deployment_id = aws_api_gateway_deployment.this.id
  stage_name    = var.stage_name
}
