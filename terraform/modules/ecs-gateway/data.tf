data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "assume_tasks" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

# What the gateway itself may do, granted to the task role.
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
