locals {
  base = "${var.subdomain}.${var.zone_name}"

  # api: REST and HTTP mappings, including a multi-level key; mtls: a truststore.
  api_domain  = "api.${local.base}"
  mtls_domain = "mtls.${local.base}"

  truststore_key = "truststore.pem"
}
