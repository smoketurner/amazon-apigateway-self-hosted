data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# What the domain gateway may do: everything both API gateways may do, plus read
# the custom domains, their mappings and routing rules, and the truststore
# (docs/deployment.md, "AWS permissions").
data "aws_iam_policy_document" "gateway_domain" {
  count = var.enable_ecs_gateway_http && var.custom_domain_zone != null ? 1 : 0

  source_policy_documents = [module.gateway_policy[0].json, module.gateway_policy_http[0].json]

  statement {
    sid     = "ReadCustomDomains"
    actions = ["apigateway:GET"]
    resources = flatten([
      for domain in [module.custom_domain[0].api_domain, module.custom_domain[0].mtls_domain] : [
        "arn:${local.partition}:apigateway:${local.region}::/v2/domainnames/${domain}",
        "arn:${local.partition}:apigateway:${local.region}::/v2/domainnames/${domain}/apimappings",
        "arn:${local.partition}:apigateway:${local.region}::/v2/domainnames/${domain}/routingrules",
      ]
    ])
  }

  statement {
    sid       = "ReadMappedRestApi"
    actions   = ["apigateway:GET"]
    resources = ["arn:${local.partition}:apigateway:${local.region}::/restapis/${module.rest_api.api_id}"]
  }

  statement {
    sid       = "ReadTruststore"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = [module.custom_domain[0].truststore_arn]
  }
}
