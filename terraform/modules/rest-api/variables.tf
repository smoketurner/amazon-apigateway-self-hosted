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

variable "user_pool_arn" {
  description = "Cognito user pool for the Cognito authorizer."
  type        = string
}

variable "queue_name" {
  description = "SQS queue for the AWS integration."
  type        = string
}

variable "table_name" {
  description = "DynamoDB table for the AWS integrations."
  type        = string
}

variable "state_machine_arn" {
  description = "State machine for the AWS integration."
  type        = string
}

variable "event_bus_name" {
  description = "Event bus for the AWS integration."
  type        = string
}

variable "cors_allowed_origin" {
  description = "Origin allowed by the CORS configuration."
  type        = string
}

variable "vpc_link" {
  description = "VPC link to add a /vpc-link route for, or null for none."
  type = object({
    id       = string
    dns_name = string
  })
  default = null
}

variable "enable_logging" {
  description = "Access and execution logging. Needs the account-wide API Gateway CloudWatch role."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "Retention for the API's log groups."
  type        = number
}

variable "enable_cache_cluster" {
  description = "Provision a stage cache cluster (billed hourly)."
  type        = bool
  default     = false
}

variable "cache_cluster_size" {
  description = "Cache cluster size in GB."
  type        = string
  default     = "0.5"
}

variable "throttle_rate_limit" {
  description = "Steady-state requests per second on /throttled."
  type        = number
}

variable "throttle_burst_limit" {
  description = "Burst limit on /throttled."
  type        = number
}
