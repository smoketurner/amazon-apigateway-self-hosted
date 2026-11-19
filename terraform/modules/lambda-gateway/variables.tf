variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "api_kind" {
  description = "API Gateway product of the API to mirror: rest or http."
  type        = string
  default     = "rest"

  validation {
    condition     = contains(["rest", "http"], var.api_kind)
    error_message = "api_kind must be rest or http."
  }
}

variable "api_id" {
  description = "ID of the API the gateway mirrors."
  type        = string
}

variable "stage_name" {
  description = "Stage the gateway mirrors."
  type        = string
}

variable "base_path" {
  description = "Path prefix the gateway serves the API under, such as /prod to match an execute-api URL. Empty serves it at the root."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Tag of the image (modules/lambda-gateway/image) in this module's ECR repository. Null creates only the repository, so the image can be pushed before the function exists."
  type        = string
  default     = null
}

variable "cpu_architecture" {
  description = "CPU architecture of the pushed image: arm64 or x86_64."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.cpu_architecture)
    error_message = "cpu_architecture must be arm64 or x86_64."
  }
}

variable "gateway_policy_json" {
  description = "IAM policy document for the function's role: what apigw may do (modules/gateway-policy)."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for the function's log group."
  type        = number
  default     = 7
}
