variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "vpc_id" {
  description = "VPC the gateway task runs in."
  type        = string
}

variable "subnet_ids" {
  description = "Public subnets for the task. It gets a public IP and reaches AWS APIs through the internet gateway."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "The gateway needs at least one subnet."
  }
}

variable "allowed_cidrs" {
  description = "CIDR blocks allowed to reach the gateway's API and admin ports. The admin port lists every backend target, so keep this to addresses you test from."
  type        = list(string)

  validation {
    condition     = !contains(var.allowed_cidrs, "0.0.0.0/0")
    error_message = "The admin port must not be open to the internet; list the addresses you test from."
  }
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

variable "image_tag" {
  description = "Tag of the apigw image in this module's ECR repository. Tags are immutable; push a new tag to deploy a new build."
  type        = string
}

variable "cpu_architecture" {
  description = "CPU architecture of the pushed image: ARM64 or X86_64."
  type        = string
  default     = "ARM64"

  validation {
    condition     = contains(["ARM64", "X86_64"], var.cpu_architecture)
    error_message = "cpu_architecture must be ARM64 or X86_64."
  }
}

variable "lambda_function_arns" {
  description = "Lambda functions the gateway invokes with its own credentials: integrations and authorizers that name no credentials role."
  type        = list(string)
  default     = []
}

variable "assumable_role_arns" {
  description = "Integration and authorizer credentials roles the gateway assumes. Each role's trust policy must also allow the task role."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "Retention for the gateway's log group."
  type        = number
  default     = 7
}
