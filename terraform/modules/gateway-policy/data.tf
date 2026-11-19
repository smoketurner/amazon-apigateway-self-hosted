data "aws_partition" "current" {}

data "aws_region" "current" {}

# What apigw itself may do, whatever it runs on.
data "aws_iam_policy_document" "gateway" {
  statement {
    sid       = "ReadApiDefinition"
    actions   = ["apigateway:GET"]
    resources = local.api_resources
  }

  dynamic "statement" {
    for_each = length(var.lambda_function_arns) > 0 ? [1] : []

    content {
      sid       = "InvokeFunctions"
      actions   = ["lambda:InvokeFunction"]
      resources = local.invocable_function_arns
    }
  }

  dynamic "statement" {
    for_each = length(var.assumable_role_arns) > 0 ? [1] : []

    content {
      sid       = "AssumeIntegrationRoles"
      actions   = ["sts:AssumeRole"]
      resources = var.assumable_role_arns
    }
  }
}
