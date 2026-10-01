locals {
  partition = data.aws_partition.current.partition
  region    = data.aws_region.current.region

  oidc_url = "token.actions.githubusercontent.com"

  subjects = coalesce(var.subjects, ["repo:${var.repository}:ref:refs/heads/main"])

  oidc_provider_arn = coalesce(
    var.oidc_provider_arn,
    try(aws_iam_openid_connect_provider.github[0].arn, null),
  )

  apigateway_arn_prefix = "arn:${local.partition}:apigateway:${local.region}::"

  rest_resources = flatten([
    for id in var.rest_api_ids : [
      "${local.apigateway_arn_prefix}/restapis/${id}/stages/${var.stage_name}",
      "${local.apigateway_arn_prefix}/restapis/${id}/stages/${var.stage_name}/exports/*",
    ]
  ])

  http_resources = flatten([
    for id in var.http_api_ids : [
      "${local.apigateway_arn_prefix}/apis/${id}/exports/*",
      "${local.apigateway_arn_prefix}/apis/${id}/stages/${var.stage_name}",
    ]
  ])
}
