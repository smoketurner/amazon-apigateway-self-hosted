output "queue_name" {
  description = "Name of the SQS target queue."
  value       = aws_sqs_queue.target.name
}

output "queue_arn" {
  description = "ARN of the SQS target queue."
  value       = aws_sqs_queue.target.arn
}

output "queue_url" {
  description = "URL of the SQS target queue."
  value       = aws_sqs_queue.target.url
}

output "table_name" {
  description = "Name of the DynamoDB target table."
  value       = aws_dynamodb_table.target.name
}

output "table_arn" {
  description = "ARN of the DynamoDB target table."
  value       = aws_dynamodb_table.target.arn
}

output "state_machine_arn" {
  description = "ARN of the EXPRESS state machine that echoes its input."
  value       = aws_sfn_state_machine.target.arn
}

output "event_bus_name" {
  description = "Name of the EventBridge target bus."
  value       = aws_cloudwatch_event_bus.target.name
}

output "event_bus_arn" {
  description = "ARN of the EventBridge target bus."
  value       = aws_cloudwatch_event_bus.target.arn
}

output "event_log_group" {
  description = "Log group that captures events sent to the bus."
  value       = aws_cloudwatch_log_group.events_catch_all.name
}

output "topic_arn" {
  description = "ARN of the SNS target topic."
  value       = aws_sns_topic.target.arn
}

output "stream_name" {
  description = "Name of the Kinesis target stream."
  value       = aws_kinesis_stream.target.name
}

output "stream_arn" {
  description = "ARN of the Kinesis target stream."
  value       = aws_kinesis_stream.target.arn
}

output "bucket_name" {
  description = "Name of the S3 target bucket."
  value       = aws_s3_bucket.target.bucket
}

output "bucket_arn" {
  description = "ARN of the S3 target bucket."
  value       = aws_s3_bucket.target.arn
}

output "empty_queue_url" {
  description = "URL of the SQS queue nothing sends to."
  value       = aws_sqs_queue.empty.url
}

output "empty_queue_arn" {
  description = "ARN of the SQS queue nothing sends to."
  value       = aws_sqs_queue.empty.arn
}

output "appconfig_application" {
  description = "Name of the AppConfig application."
  value       = aws_appconfig_application.target.name
}

output "appconfig_environment" {
  description = "Name of the AppConfig environment the configuration is deployed to."
  value       = aws_appconfig_environment.target.name
}

output "appconfig_configuration" {
  description = "Name of the AppConfig configuration profile."
  value       = aws_appconfig_configuration_profile.target.name
}

output "appconfig_application_arn" {
  description = "ARN of the AppConfig application."
  value       = aws_appconfig_application.target.arn
}
