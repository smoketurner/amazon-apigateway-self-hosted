locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  name       = "${var.name_prefix}-gateway"
  api_port   = 8443
  admin_port = 9443
  tls_dir    = "/etc/apigw/tls"

  apigateway_arn = "arn:${local.partition}:apigateway:${local.region}:"

  # The resources apigw reads to load and refresh the API (README, "AWS permissions").
  api_resources = var.api_kind == "rest" ? [
    "${local.apigateway_arn}:/restapis/${var.api_id}/stages/${var.stage_name}",
    "${local.apigateway_arn}:/restapis/${var.api_id}/stages/${var.stage_name}/exports/oas30",
    "${local.apigateway_arn}:/usageplans",
    "${local.apigateway_arn}:/usageplans/*/keys",
    "${local.apigateway_arn}:/apikeys",
    ] : [
    "${local.apigateway_arn}:/apis/${var.api_id}/stages/${var.stage_name}",
    "${local.apigateway_arn}:/apis/${var.api_id}/exports/OAS30",
  ]

  api_environment = var.api_kind == "rest" ? "APIGW_REST_API_ID" : "APIGW_HTTP_API_ID"

  # apigw has no plaintext listener, so the task makes itself a certificate
  # before the gateway starts. 65532 is the image's nonroot user.
  tls_init_command = join(" && ", [
    "apk add --no-cache openssl",
    "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=${local.name} -addext subjectAltName=DNS:${local.name} -keyout ${local.tls_dir}/tls.key -out ${local.tls_dir}/tls.crt",
    "chown 65532:65532 ${local.tls_dir}/tls.key ${local.tls_dir}/tls.crt",
  ])
}
