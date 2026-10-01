variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "function_runtime" {
  description = "Lambda runtime for the echo and authorizer functions."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for the functions' log groups."
  type        = number
}
