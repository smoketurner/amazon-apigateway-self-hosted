output "role_arn" {
  description = "Role the parity workflow assumes through GitHub OIDC."
  value       = aws_iam_role.ci.arn
}
