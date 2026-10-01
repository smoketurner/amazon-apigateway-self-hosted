variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for the EventBridge capture log group."
  type        = number
}
