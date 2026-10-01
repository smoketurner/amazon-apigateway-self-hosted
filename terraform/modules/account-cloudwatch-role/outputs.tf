output "role_arn" {
  description = "Role API Gateway uses to write CloudWatch logs for the account."
  value       = aws_iam_role.this.arn
}
