variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "stage_name" {
  description = "Stage the API is deployed to."
  type        = string
}

variable "stage_variables" {
  description = "Stage variables (the echo host and its shared secret)."
  type        = map(string)
  sensitive   = true
}

variable "echo_invocation_uri" {
  description = "Integration URI of the echo Lambda."
  type        = string
}

variable "authorizer_invocation_uri" {
  description = "Authorizer URI of the authorizer Lambda."
  type        = string
}

variable "invoke_role_arn" {
  description = "Role API Gateway assumes for integrations and authorizers."
  type        = string
}

variable "cognito_issuer" {
  description = "Issuer URL for the JWT authorizer."
  type        = string
}

variable "cognito_client_id" {
  description = "Audience for the JWT authorizer."
  type        = string
}

variable "queue_url" {
  description = "SQS queue the SQS-SendMessage subtype route sends to."
  type        = string
}

variable "event_bus_name" {
  description = "Event bus the EventBridge-PutEvents subtype route publishes to."
  type        = string
}

variable "state_machine_arn" {
  description = "State machine the StepFunctions-StartSyncExecution subtype route starts."
  type        = string
}

variable "stream_name" {
  description = "Kinesis stream the Kinesis-PutRecord subtype route puts records on."
  type        = string
}

variable "cors_allowed_origin" {
  description = "Origin allowed by the CORS configuration."
  type        = string
}

variable "enable_logging" {
  description = "Access logging."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention for the API's log group."
  type        = number
}

variable "throttle_rate_limit" {
  description = "Steady-state requests per second on GET /throttled."
  type        = number
}

variable "throttle_burst_limit" {
  description = "Burst limit on GET /throttled."
  type        = number
}
