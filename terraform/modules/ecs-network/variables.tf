variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "cidr_block" {
  description = "CIDR block of the VPC. Its public subnets are /26 blocks carved from it."
  type        = string
  default     = "10.83.0.0/24"
}

variable "availability_zones" {
  description = "Availability zones to place one public subnet in each."
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) > 0 && length(var.availability_zones) <= 4
    error_message = "Name between one and four availability zones."
  }
}
