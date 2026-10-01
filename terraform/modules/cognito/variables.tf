variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "test_username" {
  description = "User name of the test user the parity runner signs in as."
  type        = string
  default     = "parity-user"
}
