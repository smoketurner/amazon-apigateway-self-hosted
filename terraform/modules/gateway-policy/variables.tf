variable "api_kind" {
  description = "API Gateway product of the API the gateway mirrors: rest or http."
  type        = string

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

variable "lambda_function_arns" {
  description = "Lambda functions the gateway invokes with its own credentials: integrations and authorizers that name no credentials role."
  type        = list(string)
  default     = []
}

variable "assumable_role_arns" {
  description = "Integration and authorizer credentials roles the gateway assumes. Each role's trust policy must also allow the gateway's role."
  type        = list(string)
  default     = []
}
