variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "repository" {
  description = "owner/name of the repository whose workflows may assume the CI role."
  type        = string
}

variable "subjects" {
  description = "OIDC subject claims allowed to assume the role. Null allows the repository's main branch."
  type        = list(string)
  default     = null
}

variable "oidc_provider_arn" {
  description = "Existing GitHub OIDC provider ARN. Null creates one (an account can only have one per URL)."
  type        = string
  default     = null
}

variable "stage_name" {
  description = "Stage of the reference APIs the role may read."
  type        = string
}

variable "rest_api_ids" {
  description = "REST APIs whose stage and export the role may read."
  type        = list(string)
}

variable "http_api_ids" {
  description = "HTTP APIs whose stage and export the role may read."
  type        = list(string)
}
