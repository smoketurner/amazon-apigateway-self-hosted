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
