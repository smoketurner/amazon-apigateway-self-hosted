locals {
  github_oidc_url = "token.actions.githubusercontent.com"

  github_subjects = coalesce(var.github_subjects, ["repo:${var.github_repository}:ref:refs/heads/main"])

  github_oidc_provider_arn = coalesce(
    var.github_oidc_provider_arn,
    try(aws_iam_openid_connect_provider.github[0].arn, null),
  )
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.github_oidc_provider_arn == null ? 1 : 0

  url            = "https://${local.github_oidc_url}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.github_oidc_url}:sub"
      values   = local.github_subjects
    }
  }
}

resource "aws_iam_role" "github_ci" {
  name                 = "${var.name_prefix}-github-ci"
  assume_role_policy   = data.aws_iam_policy_document.github_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_ci" {
  statement {
    sid     = "ReadRestExportsAndStage"
    actions = ["apigateway:GET"]
    resources = [
      "arn:${local.partition}:apigateway:${var.region}::/restapis/${aws_api_gateway_rest_api.reference.id}/stages/${var.stage_name}",
      "arn:${local.partition}:apigateway:${var.region}::/restapis/${aws_api_gateway_rest_api.reference.id}/stages/${var.stage_name}/exports/*",
      "arn:${local.partition}:apigateway:${var.region}::/restapis/${aws_api_gateway_rest_api.policy.id}/stages/${var.stage_name}",
      "arn:${local.partition}:apigateway:${var.region}::/restapis/${aws_api_gateway_rest_api.policy.id}/stages/${var.stage_name}/exports/*",
    ]
  }

  statement {
    sid     = "ReadHttpExportsAndStage"
    actions = ["apigateway:GET"]
    resources = [
      "arn:${local.partition}:apigateway:${var.region}::/apis/${aws_apigatewayv2_api.reference.id}/exports/*",
      "arn:${local.partition}:apigateway:${var.region}::/apis/${aws_apigatewayv2_api.reference.id}/stages/${var.stage_name}",
    ]
  }
}

resource "aws_iam_role_policy" "github_ci" {
  name   = "read-reference-apis"
  role   = aws_iam_role.github_ci.id
  policy = data.aws_iam_policy_document.github_ci.json
}
