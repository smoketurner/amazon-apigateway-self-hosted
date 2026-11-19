output "repository_url" {
  description = "ECR repository to push the apigw image to."
  value       = aws_ecr_repository.this.repository_url
}

output "cluster_name" {
  description = "ECS cluster running the gateway."
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "ECS service running the gateway."
  value       = aws_ecs_service.this.name
}

output "task_role_arn" {
  description = "Role the gateway's AWS calls are made as. Add it to the trust policy of each integration role the gateway assumes."
  value       = aws_iam_role.task.arn
}

output "log_group_name" {
  description = "Log group holding the gateway's logs."
  value       = aws_cloudwatch_log_group.this.name
}
