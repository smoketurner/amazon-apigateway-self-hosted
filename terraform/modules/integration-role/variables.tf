variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "lambda_function_arns" {
  description = "Lambda functions API Gateway invokes as integrations or authorizers."
  type        = list(string)
}

variable "queue_arn" {
  description = "SQS queue the AWS integrations send to."
  type        = string
}

variable "table_arn" {
  description = "DynamoDB table the AWS integrations read and write."
  type        = string
}

variable "state_machine_arn" {
  description = "State machine the AWS integrations start."
  type        = string
}

variable "event_bus_arn" {
  description = "Event bus the AWS integrations publish to."
  type        = string
}

variable "empty_queue_arn" {
  description = "SQS queue the receive, delete, and purge subtypes act on."
  type        = string
}

variable "appconfig_application_arn" {
  description = "AppConfig application the GetConfiguration subtype reads."
  type        = string
}

variable "topic_arn" {
  description = "SNS topic the AWS integrations publish to."
  type        = string
}

variable "stream_arn" {
  description = "Kinesis stream the AWS integrations put records on."
  type        = string
}

variable "bucket_arn" {
  description = "S3 bucket the AWS integrations write and read objects in."
  type        = string
}

variable "trusted_principal_arns" {
  description = "IAM principals, besides API Gateway, allowed to assume the role: the identity of each self-hosted gateway."
  type        = list(string)
  default     = []
}
