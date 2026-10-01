locals {
  name = "${var.name_prefix}-http"

  openapi = yamldecode(templatefile("${path.module}/templates/openapi.yaml.tftpl", {
    name                      = local.name
    echo_invocation_uri       = var.echo_invocation_uri
    authorizer_invocation_uri = var.authorizer_invocation_uri
    invoke_role_arn           = var.invoke_role_arn
    cors_origin               = var.cors_allowed_origin
    cognito_issuer            = var.cognito_issuer
    cognito_client_id         = var.cognito_client_id
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
