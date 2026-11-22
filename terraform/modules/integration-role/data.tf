data "aws_iam_policy_document" "assume" {
  # No aws:SourceAccount condition: with one, every REST and HTTP API route
  # that names this role as its integration or authorizer credentials answered
  # 500, because API Gateway could not assume the role.
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }

  # A self-hosted gateway calls integrations as itself, so it assumes this role
  # the way API Gateway does (docs/deployment.md, "Integration roles").
  dynamic "statement" {
    for_each = length(var.trusted_principal_arns) > 0 ? [1] : []

    content {
      actions = ["sts:AssumeRole"]

      principals {
        type        = "AWS"
        identifiers = var.trusted_principal_arns
      }
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
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:PurgeQueue"]
    resources = [var.empty_queue_arn]
  }

  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem"]
    resources = [var.table_arn]
  }

  statement {
    actions   = ["states:StartSyncExecution", "states:StartExecution"]
    resources = [var.state_machine_arn]
  }

  # StopExecution names an execution, not the state machine.
  statement {
    actions   = ["states:StopExecution"]
    resources = ["${replace(var.state_machine_arn, ":stateMachine:", ":execution:")}:*"]
  }

  statement {
    actions   = ["appconfig:GetConfiguration"]
    resources = ["${var.appconfig_application_arn}/*"]
  }

  statement {
    actions   = ["events:PutEvents"]
    resources = [var.event_bus_arn]
  }

  statement {
    actions   = ["sns:Publish"]
    resources = [var.topic_arn]
  }

  statement {
    actions   = ["kinesis:PutRecord"]
    resources = [var.stream_arn]
  }

  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${var.bucket_arn}/*"]
  }

  # Without ListBucket, S3 answers a missing object with 403 instead of 404.
  statement {
    actions   = ["s3:ListBucket"]
    resources = [var.bucket_arn]
  }
}
