variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "zone_name" {
  description = "Existing public hosted zone the domains are created under. Only new records are added to it."
  type        = string
}

variable "subdomain" {
  description = "Label under zone_name that every record this module creates sits below, so it cannot collide with existing records."
  type        = string
  default     = "parity"
}

variable "rest_api_id" {
  description = "Reference REST API mapped to the domains."
  type        = string
}

variable "http_api_id" {
  description = "Reference HTTP API mapped to the plain domain."
  type        = string
}

variable "stage_name" {
  description = "Stage of both APIs that the mappings serve."
  type        = string
}
