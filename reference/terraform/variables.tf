variable "region" {
  description = "AWS region for every resource in the stack."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names. Change it to run several copies in one account."
  type        = string
  default     = "apigw-ref"
}

variable "stage_name" {
  description = "Stage name used by both reference APIs."
  type        = string
  default     = "ref"
}

variable "log_retention_days" {
  description = "Retention for every CloudWatch log group the stack creates."
  type        = number
  default     = 7
}

variable "enable_logging" {
  description = "Turn on access logs and execution logging. REST APIs need the account-wide CloudWatch role (see manage_account_cloudwatch_role)."
  type        = bool
  default     = false
}

variable "manage_account_cloudwatch_role" {
  description = "Create the account-wide API Gateway CloudWatch role and set it in aws_api_gateway_account. This overwrites the account's current setting, so leave it false when the account already has one."
  type        = bool
  default     = false
}

variable "enable_cache_cluster" {
  description = "Provision a REST API stage cache cluster. It bills hourly while it exists; leave false unless you are testing caching."
  type        = bool
  default     = false
}

variable "cache_cluster_size" {
  description = "Cache cluster size in GB when enable_cache_cluster is true."
  type        = string
  default     = "0.5"
}

variable "enable_vpc_link" {
  description = "Add a VPC-link route to the REST API, backed by an internal NLB. The NLB bills hourly."
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC for the VPC-link target group. Required when enable_vpc_link is true."
  type        = string
  default     = null
}

variable "vpc_link_subnet_ids" {
  description = "Subnets for the internal NLB behind the VPC link. Required when enable_vpc_link is true."
  type        = list(string)
  default     = []
}

variable "vpc_link_target_ips" {
  description = "Optional IP addresses registered in the VPC-link target group on port 80."
  type        = list(string)
  default     = []
}

variable "policy_restricted_cidrs" {
  description = "CIDRs allowed to call /ip-restricted on the resource-policy API. The default admits every IPv4 and IPv6 caller; narrow it to record a 403."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}

variable "github_repository" {
  description = "owner/name of the repository whose workflows may assume the CI role."
  type        = string
  default     = "smoketurner/amazon-apigateway-self-hosted"
}

variable "github_subjects" {
  description = "OIDC subject claims allowed to assume the CI role. Defaults to the repository's main branch, where the nightly workflow runs."
  type        = list(string)
  default     = null
}

variable "github_oidc_provider_arn" {
  description = "Existing GitHub OIDC provider ARN. When null, the stack creates the provider (an account can only have one per URL)."
  type        = string
  default     = null
}

variable "function_runtime" {
  description = "Lambda runtime for the echo and authorizer functions."
  type        = string
  default     = "python3.13"
}

variable "throttle_rate_limit" {
  description = "Steady-state requests per second on the throttled routes."
  type        = number
  default     = 1
}

variable "throttle_burst_limit" {
  description = "Burst limit on the throttled routes."
  type        = number
  default     = 1
}

variable "cors_allowed_origin" {
  description = "Origin allowed by the CORS configuration on both APIs."
  type        = string
  default     = "https://example.com"
}
