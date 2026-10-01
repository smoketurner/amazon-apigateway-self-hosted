variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "vpc_id" {
  description = "VPC for the target group."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets for the internal NLB."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "The VPC link needs at least one subnet."
  }
}

variable "target_ips" {
  description = "IP addresses registered in the target group on port 80."
  type        = list(string)
  default     = []
}
