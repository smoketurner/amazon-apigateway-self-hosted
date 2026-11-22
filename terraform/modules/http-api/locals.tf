locals {
  name = "${var.name_prefix}-http"

  openapi = yamldecode(templatefile("${path.module}/templates/openapi.yaml.tftpl", {
    name                      = local.name
    echo_invocation_uri       = var.echo_invocation_uri
    authorizer_invocation_uri = var.authorizer_invocation_uri
    invoke_role_arn           = var.invoke_role_arn
    cognito_issuer            = var.cognito_issuer
    cognito_client_id         = var.cognito_client_id
    queue_url                 = var.queue_url
    event_bus_name            = var.event_bus_name
    state_machine_arn         = var.state_machine_arn
    stream_name               = var.stream_name
  }))

  access_log_format = jsonencode({
    requestId        = "$context.requestId"
    extendedRequest  = "$context.extendedRequestId"
    ip               = "$context.identity.sourceIp"
    requestTime      = "$context.requestTime"
    httpMethod       = "$context.httpMethod"
    routeKey         = "$context.routeKey"
    status           = "$context.status"
    protocol         = "$context.protocol"
    responseLength   = "$context.responseLength"
    errorMessage     = "$context.error.message"
    authorizerError  = "$context.authorizer.error"
    integrationError = "$context.integrationErrorMessage"
  })
}
