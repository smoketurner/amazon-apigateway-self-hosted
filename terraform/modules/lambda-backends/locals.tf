locals {
  partition = data.aws_partition.current.partition
  region    = data.aws_region.current.region

  invocation_prefix = "arn:${local.partition}:apigateway:${local.region}:lambda:path/2015-03-31/functions"

  echo_host = trimsuffix(trimprefix(aws_lambda_function_url.echo.function_url, "https://"), "/")
}
