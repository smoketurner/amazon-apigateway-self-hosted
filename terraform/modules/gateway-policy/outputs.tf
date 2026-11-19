output "json" {
  description = "IAM policy document granting what apigw needs to mirror the API."
  value       = data.aws_iam_policy_document.gateway.json
}
