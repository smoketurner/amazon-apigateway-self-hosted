resource "aws_cognito_user_pool" "this" {
  name                     = "${var.name_prefix}-users"
  auto_verified_attributes = []

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length    = 16
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = false
  }
}

resource "aws_cognito_user_pool_client" "this" {
  name         = "${var.name_prefix}-client"
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret = false
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]
}

resource "random_password" "test_user" {
  length      = 24
  special     = false
  min_lower   = 2
  min_upper   = 2
  min_numeric = 2
}

resource "aws_cognito_user" "test" {
  user_pool_id   = aws_cognito_user_pool.this.id
  username       = var.test_username
  password       = random_password.test_user.result
  message_action = "SUPPRESS"
}
