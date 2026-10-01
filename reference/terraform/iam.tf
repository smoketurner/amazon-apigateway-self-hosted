data "aws_iam_policy_document" "apigateway_assume" {
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

resource "aws_iam_role" "apigateway_invoke" {
  name               = "${var.name_prefix}-apigateway-invoke"
  assume_role_policy = data.aws_iam_policy_document.apigateway_assume.json
}

data "aws_iam_policy_document" "apigateway_invoke" {
  statement {
    actions = ["lambda:InvokeFunction"]
    resources = [
      aws_lambda_function.echo.arn,
      aws_lambda_function.authorizer.arn,
    ]
  }

  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.target.arn]
  }

  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.target.arn]
  }

  statement {
    actions   = ["states:StartSyncExecution"]
    resources = [aws_sfn_state_machine.target.arn]
  }

  statement {
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.target.arn]
  }
}

resource "aws_iam_role_policy" "apigateway_invoke" {
  name   = "targets"
  role   = aws_iam_role.apigateway_invoke.id
  policy = data.aws_iam_policy_document.apigateway_invoke.json
}

data "aws_iam_policy_document" "apigateway_cloudwatch_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "apigateway_cloudwatch" {
  count = var.manage_account_cloudwatch_role ? 1 : 0

  name               = "${var.name_prefix}-apigateway-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.apigateway_cloudwatch_assume.json
}

resource "aws_iam_role_policy_attachment" "apigateway_cloudwatch" {
  count = var.manage_account_cloudwatch_role ? 1 : 0

  role       = aws_iam_role.apigateway_cloudwatch[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "this" {
  count = var.manage_account_cloudwatch_role ? 1 : 0

  cloudwatch_role_arn = aws_iam_role.apigateway_cloudwatch[0].arn

  depends_on = [aws_iam_role_policy_attachment.apigateway_cloudwatch]
}
