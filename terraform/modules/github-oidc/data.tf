data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.oidc_url}:sub"
      values   = local.subjects
    }
  }
}

data "aws_iam_policy_document" "read_reference_apis" {
  statement {
    sid       = "ReadRestExportsAndStage"
    actions   = ["apigateway:GET"]
    resources = local.rest_resources
  }

  statement {
    sid       = "ReadHttpExportsAndStage"
    actions   = ["apigateway:GET"]
    resources = local.http_resources
  }
}
