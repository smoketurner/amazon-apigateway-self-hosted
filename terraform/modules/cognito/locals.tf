locals {
  region = data.aws_region.current.region

  issuer = "https://cognito-idp.${local.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}
