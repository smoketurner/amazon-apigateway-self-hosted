resource "aws_sqs_queue" "target" {
  name                      = "${var.name_prefix}-target"
  message_retention_seconds = 3600
  sqs_managed_sse_enabled   = true
}

resource "aws_dynamodb_table" "target" {
  name         = "${var.name_prefix}-target"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

data "aws_iam_policy_document" "sfn_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${var.name_prefix}-sfn"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

resource "aws_sfn_state_machine" "target" {
  name     = "${var.name_prefix}-target"
  role_arn = aws_iam_role.sfn.arn
  type     = "EXPRESS"

  definition = jsonencode({
    Comment = "Returns its input so the parity runner can see what API Gateway sent."
    StartAt = "Echo"
    States = {
      Echo = {
        Type = "Pass"
        End  = true
      }
    }
  })
}

resource "aws_cloudwatch_event_bus" "target" {
  name = "${var.name_prefix}-target"
}

resource "aws_cloudwatch_log_group" "events_catch_all" {
  name              = "/aws/events/${var.name_prefix}-target"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_event_rule" "catch_all" {
  name           = "${var.name_prefix}-catch-all"
  event_bus_name = aws_cloudwatch_event_bus.target.name
  event_pattern  = jsonencode({ source = ["apigw.reference"] })
}

data "aws_iam_policy_document" "events_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.events_catch_all.arn}:*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "events_logs" {
  policy_name     = "${var.name_prefix}-events-logs"
  policy_document = data.aws_iam_policy_document.events_logs.json
}

resource "aws_cloudwatch_event_target" "catch_all_logs" {
  rule           = aws_cloudwatch_event_rule.catch_all.name
  event_bus_name = aws_cloudwatch_event_bus.target.name
  arn            = aws_cloudwatch_log_group.events_catch_all.arn

  depends_on = [aws_cloudwatch_log_resource_policy.events_logs]
}

resource "aws_cognito_user_pool" "reference" {
  name                     = "${var.name_prefix}-users"
  auto_verified_attributes = []

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length    = 16
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = false
  }
}

resource "aws_cognito_user_pool_client" "reference" {
  name         = "${var.name_prefix}-client"
  user_pool_id = aws_cognito_user_pool.reference.id

  generate_secret = false
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]
}

resource "random_password" "cognito_user" {
  length      = 24
  special     = false
  min_lower   = 2
  min_upper   = 2
  min_numeric = 2
}

resource "aws_cognito_user" "reference" {
  user_pool_id   = aws_cognito_user_pool.reference.id
  username       = "parity-user"
  password       = random_password.cognito_user.result
  message_action = "SUPPRESS"
}

locals {
  cognito_issuer = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.reference.id}"
}
