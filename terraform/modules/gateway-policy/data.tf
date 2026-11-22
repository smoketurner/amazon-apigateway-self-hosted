data "aws_partition" "current" {}

data "aws_region" "current" {}

# What apigw itself may do, whatever it runs on.
data "aws_iam_policy_document" "gateway" {
  statement {
    sid       = "${local.sid_prefix}ReadApiDefinition"
    actions   = ["apigateway:GET"]
    resources = local.api_resources
  }

  dynamic "statement" {
    for_each = length(var.lambda_function_arns) > 0 ? [1] : []

    content {
      sid       = "${local.sid_prefix}InvokeFunctions"
      actions   = ["lambda:InvokeFunction"]
      resources = local.invocable_function_arns
    }
  }

  # docs/deployment.md, "AWS permissions": access and execution logs.
  dynamic "statement" {
    for_each = length(var.log_group_arns) > 0 ? [1] : []

    content {
      sid       = "${local.sid_prefix}WriteLogs"
      actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
      resources = concat(var.log_group_arns, [for arn in var.log_group_arns : "${arn}:*"])
    }
  }

  dynamic "statement" {
    for_each = length(var.assumable_role_arns) > 0 ? [1] : []

    content {
      sid       = "${local.sid_prefix}AssumeIntegrationRoles"
      actions   = ["sts:AssumeRole"]
      resources = var.assumable_role_arns
    }
  }
}
