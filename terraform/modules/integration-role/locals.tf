locals {
  account_id = data.aws_caller_identity.current.account_id

  role_name = "${var.name_prefix}-apigateway-invoke"
}
