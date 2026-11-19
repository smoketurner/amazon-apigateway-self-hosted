locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  name       = "${var.name_prefix}-gateway"
  api_port   = 8443
  admin_port = 9443
  tls_dir    = "/etc/apigw/tls"

  log_group_name       = "/ecs/${local.name}"
  execution_policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
  image                = "${aws_ecr_repository.this.repository_url}:${var.image_tag}"
  tls_init_image       = "public.ecr.aws/docker/library/alpine:3.24"

  # The smallest Fargate size.
  task_cpu    = 256
  task_memory = 512

  # Above the 30 s connection drain that follows SIGTERM.
  stop_timeout_seconds = 45

  # Functions are invoked by ARN or by a qualified ARN (alias or version).
  invocable_function_arns = concat(var.lambda_function_arns, [for arn in var.lambda_function_arns : "${arn}:*"])

  apigateway_arn = "arn:${local.partition}:apigateway:${local.region}:"

  # The resources apigw reads to load and refresh the API (README, "AWS permissions").
  api_resources = var.api_kind == "rest" ? [
    "${local.apigateway_arn}:/restapis/${var.api_id}/stages/${var.stage_name}",
    "${local.apigateway_arn}:/restapis/${var.api_id}/stages/${var.stage_name}/exports/oas30",
    "${local.apigateway_arn}:/usageplans",
    "${local.apigateway_arn}:/usageplans/*/keys",
    "${local.apigateway_arn}:/apikeys",
    ] : [
    "${local.apigateway_arn}:/apis/${var.api_id}/stages/${var.stage_name}",
    "${local.apigateway_arn}:/apis/${var.api_id}/exports/OAS30",
  ]

  api_environment = var.api_kind == "rest" ? "APIGW_REST_API_ID" : "APIGW_HTTP_API_ID"

  # apigw has no plaintext listener, so the task makes itself a certificate
  # before the gateway starts. 65532 is the image's nonroot user.
  tls_init_command = join(" && ", [
    "apk add --no-cache openssl",
    "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=${local.name} -addext subjectAltName=DNS:${local.name} -keyout ${local.tls_dir}/tls.key -out ${local.tls_dir}/tls.crt",
    "chown 65532:65532 ${local.tls_dir}/tls.key ${local.tls_dir}/tls.crt",
  ])

  log_configuration = {
    for container in ["tls-init", "apigw"] : container => {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = local.region
        awslogs-stream-prefix = container
      }
    }
  }

  container_definitions = [
    {
      name       = "tls-init"
      image      = local.tls_init_image
      essential  = false
      entryPoint = ["sh", "-ec"]
      command    = [local.tls_init_command]
      mountPoints = [
        { sourceVolume = "tls", containerPath = local.tls_dir, readOnly = false },
      ]
      logConfiguration = local.log_configuration["tls-init"]
    },
    {
      name      = "apigw"
      image     = local.image
      essential = true
      dependsOn = [
        { containerName = "tls-init", condition = "SUCCESS" },
      ]
      stopTimeout = local.stop_timeout_seconds
      environment = [
        { name = local.api_environment, value = var.api_id },
        { name = "APIGW_STAGE", value = var.stage_name },
        { name = "APIGW_LISTEN", value = "0.0.0.0:${local.api_port}" },
        { name = "APIGW_ADMIN_LISTEN", value = "0.0.0.0:${local.admin_port}" },
        { name = "APIGW_TLS_CERT", value = "${local.tls_dir}/tls.crt" },
        { name = "APIGW_TLS_KEY", value = "${local.tls_dir}/tls.key" },
        { name = "APIGW_CONFIG_CACHE", value = "/var/cache/apigw/config.json" },
        { name = "AWS_REGION", value = local.region },
      ]
      portMappings = [
        { containerPort = local.api_port, protocol = "tcp" },
        { containerPort = local.admin_port, protocol = "tcp" },
      ]
      mountPoints = [
        { sourceVolume = "tls", containerPath = local.tls_dir, readOnly = true },
      ]
      logConfiguration = local.log_configuration["apigw"]
    },
  ]
}
