locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  name = "${var.name_prefix}-rest"

  openapi = yamldecode(templatefile("${path.module}/templates/openapi.yaml.tftpl", {
    name                      = local.name
    partition                 = local.partition
    region                    = local.region
    account_id                = local.account_id
    echo_invocation_uri       = var.echo_invocation_uri
    authorizer_invocation_uri = var.authorizer_invocation_uri
    invoke_role_arn           = var.invoke_role_arn
    user_pool_arn             = var.user_pool_arn
    queue_name                = var.queue_name
    table_name                = var.table_name
    state_machine_arn         = var.state_machine_arn
    event_bus_name            = var.event_bus_name
    cors_origin               = var.cors_allowed_origin
    enable_vpc_link           = var.vpc_link != null
    vpc_link_id               = try(var.vpc_link.id, "")
    vpc_link_dns_name         = try(var.vpc_link.dns_name, "")
  }))

  access_log_format = jsonencode({
    requestId        = "$context.requestId"
    extendedRequest  = "$context.extendedRequestId"
    ip               = "$context.identity.sourceIp"
    requestTime      = "$context.requestTime"
    httpMethod       = "$context.httpMethod"
    resourcePath     = "$context.resourcePath"
    status           = "$context.status"
    protocol         = "$context.protocol"
    responseLength   = "$context.responseLength"
    errorMessage     = "$context.error.message"
    authorizerError  = "$context.authorizer.error"
    integrationError = "$context.integration.error"
  })
}
