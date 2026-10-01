locals {
  partition = data.aws_partition.current.partition

  push_to_logs_policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}
