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

resource "aws_sns_topic" "target" {
  name = "${var.name_prefix}-target"
}

# One provisioned shard: the cheapest stream that takes a PutRecord.
resource "aws_kinesis_stream" "target" {
  name             = "${var.name_prefix}-target"
  shard_count      = 1
  retention_period = 24

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }
}

resource "aws_s3_bucket" "target" {
  bucket        = local.bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "target" {
  bucket = aws_s3_bucket.target.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "target" {
  bucket = aws_s3_bucket.target.id

  rule {
    id     = "expire-parity-objects"
    status = "Enabled"

    filter {}

    expiration {
      days = 1
    }
  }
}

# Nothing sends to this queue, so a ReceiveMessage of it answers the same empty result
# behind API Gateway and behind apigw.
resource "aws_sqs_queue" "empty" {
  name                      = "${var.name_prefix}-empty"
  message_retention_seconds = 60
  sqs_managed_sse_enabled   = true
}

resource "aws_appconfig_application" "target" {
  name = "${var.name_prefix}-target"
}

resource "aws_appconfig_environment" "target" {
  name           = "parity"
  application_id = aws_appconfig_application.target.id
}

resource "aws_appconfig_configuration_profile" "target" {
  name           = "flags"
  application_id = aws_appconfig_application.target.id
  location_uri   = "hosted"
}

resource "aws_appconfig_hosted_configuration_version" "target" {
  application_id           = aws_appconfig_application.target.id
  configuration_profile_id = aws_appconfig_configuration_profile.target.configuration_profile_id
  content_type             = "application/json"
  content                  = jsonencode({ parity = true })
}

resource "aws_appconfig_deployment" "target" {
  application_id           = aws_appconfig_application.target.id
  environment_id           = aws_appconfig_environment.target.environment_id
  configuration_profile_id = aws_appconfig_configuration_profile.target.configuration_profile_id
  configuration_version    = aws_appconfig_hosted_configuration_version.target.version_number
  deployment_strategy_id   = "AppConfig.AllAtOnce"
}
