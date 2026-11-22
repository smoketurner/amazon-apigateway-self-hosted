locals {
  partition = data.aws_partition.current.partition
  region    = data.aws_region.current.region

  apigateway_arn = "arn:${local.partition}:apigateway:${local.region}:"

  # The resources apigw reads to load and refresh the API (README, "AWS permissions").
  api_resources = var.api_kind == "rest" ? [
    "${local.apigateway_arn}:/restapis/${var.api_id}/stages/${var.stage_name}",
    "${local.apigateway_arn}:/restapis/${var.api_id}/stages/${var.stage_name}/exports/oas30",
    # Optional for apigw: it fills in $context.resourceId.
    "${local.apigateway_arn}:/restapis/${var.api_id}/resources",
    "${local.apigateway_arn}:/usageplans",
    "${local.apigateway_arn}:/usageplans/*/keys",
    "${local.apigateway_arn}:/apikeys",
    ] : [
    "${local.apigateway_arn}:/apis/${var.api_id}/stages/${var.stage_name}",
    "${local.apigateway_arn}:/apis/${var.api_id}/exports/OAS30",
  ]

  # Functions are invoked by ARN or by a qualified ARN (alias or version).
  invocable_function_arns = concat(var.lambda_function_arns, [for arn in var.lambda_function_arns : "${arn}:*"])
}
