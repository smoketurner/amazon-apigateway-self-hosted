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
