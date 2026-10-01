terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.67.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.9.1"
    }
  }
}
