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

resource "aws_iam_role" "sfn" {
  name               = "${var.name_prefix}-sfn"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

resource "aws_sfn_state_machine" "target" {
  name       = "${var.name_prefix}-target"
  role_arn   = aws_iam_role.sfn.arn
  type       = "EXPRESS"
  definition = jsonencode(local.state_machine_definition)
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
  event_pattern  = jsonencode({ source = [local.event_source] })
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
