locals {
  partition = data.aws_partition.current.partition

  name                 = "${var.name_prefix}-gateway-lambda"
  log_group_name       = "/aws/lambda/${local.name}"
  execution_policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  deploy_function      = var.image_tag != null
  image_uri            = local.deploy_function ? "${aws_ecr_repository.this.repository_url}:${var.image_tag}" : null

  api_environment = var.api_kind == "rest" ? "APIGW_REST_API_ID" : "APIGW_HTTP_API_ID"

  # apigw loads the API definition while the function initializes, and an
  # integration may take API Gateway's full 29 seconds.
  memory_mb       = 512
  timeout_seconds = 30

  environment = {
    (local.api_environment) = var.api_id
    APIGW_STAGE             = var.stage_name
  }
}
