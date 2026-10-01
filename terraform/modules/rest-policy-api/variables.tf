variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "stage_name" {
  description = "Stage the API is deployed to."
  type        = string
}

variable "restricted_cidrs" {
  description = "CIDRs allowed to call /ip-restricted."
  type        = list(string)
}
