data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

data "aws_iam_policy_document" "invoke" {
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = var.lambda_function_arns
  }

  statement {
    actions   = ["sqs:SendMessage"]
    resources = [var.queue_arn]
  }

  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem"]
    resources = [var.table_arn]
  }

  statement {
    actions   = ["states:StartSyncExecution"]
    resources = [var.state_machine_arn]
  }

  statement {
    actions   = ["events:PutEvents"]
    resources = [var.event_bus_arn]
  }
}
