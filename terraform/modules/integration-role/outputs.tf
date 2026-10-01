output "role_arn" {
  description = "Role API Gateway assumes to call integrations and authorizers (the integrations' credentials)."
  value       = aws_iam_role.this.arn
}
