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
        "arn:${local.partition}:apigateway:${local.region}::/domainnames/${domain}",
        "arn:${local.partition}:apigateway:${local.region}::/domainnames/${domain}/apimappings",
        "arn:${local.partition}:apigateway:${local.region}::/domainnames/${domain}/routingrules",
      ]
    ])
  }

  # apigw tells a REST from an HTTP API by GetRestApi on every mapped API,
  # which answers not found for an HTTP API.
  statement {
    sid     = "ReadMappedApis"
    actions = ["apigateway:GET"]
    resources = [
      for id in [module.rest_api.api_id, module.http_api.api_id] :
      "arn:${local.partition}:apigateway:${local.region}::/restapis/${id}"
    ]
  }

  dynamic "statement" {
    for_each = var.custom_domain_export_certificate ? [true] : []
    content {
      sid       = "ExportDomainCertificate"
      actions   = ["acm:DescribeCertificate", "acm:ExportCertificate"]
      resources = [module.custom_domain[0].certificate_arn]
    }
  }

  statement {
    sid       = "ReadTruststore"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = [module.custom_domain[0].truststore_arn]
  }
}
