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

  # apigw has no plaintext listener, so the task makes itself a certificate
  # before the gateway starts. 65532 is the image's nonroot user.
  tls_init_command = join(" && ", [
    "apk add --no-cache openssl",
    "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=${local.name} -addext subjectAltName=DNS:${local.name} -keyout ${local.tls_dir}/tls.key -out ${local.tls_dir}/tls.crt",
    "chown 65532:65532 ${local.tls_dir}/tls.key ${local.tls_dir}/tls.crt",
  ])

  tls_init_log_configuration = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = aws_cloudwatch_log_group.this.name
      awslogs-region        = local.region
      awslogs-stream-prefix = "tls-init"
    }
  }

  # Every API the task mirrors: the one it was created for under the name
  # "apigw", then the additional ones as "apigw-<name>".
  apis = merge(
    {
      apigw = {
        kind       = var.api_kind
        id         = var.api_id
        api_port   = local.api_port
        admin_port = local.admin_port
      }
    },
    {
      for name, api in var.additional_apis : "apigw-${name}" => {
        kind       = api.kind
        id         = api.id
        api_port   = api.api_port
        admin_port = api.admin_port
      }
    },
  )

  # The ports of the additional APIs, which the security group opens to the
  # same addresses as the first one's.
  additional_ingress = {
    for pair in setproduct(var.allowed_cidrs, flatten([for api in values(var.additional_apis) : [api.api_port, api.admin_port]])) :
    "${pair[0]}-${pair[1]}" => { cidr = pair[0], port = pair[1] }
  }

  gateway_containers = [
    for name, api in local.apis : {
      name      = name
      image     = local.image
      essential = true
      dependsOn = [
        { containerName = "tls-init", condition = "SUCCESS" },
      ]
      stopTimeout = local.stop_timeout_seconds
      environment = [
        { name = api.kind == "rest" ? "APIGW_REST_API_ID" : "APIGW_HTTP_API_ID", value = api.id },
        { name = "APIGW_STAGE", value = var.stage_name },
        { name = "APIGW_BASE_PATH", value = var.base_path },
        { name = "APIGW_LISTEN", value = "0.0.0.0:${api.api_port}" },
        { name = "APIGW_ADMIN_LISTEN", value = "0.0.0.0:${api.admin_port}" },
        { name = "APIGW_TLS_CERT", value = "${local.tls_dir}/tls.crt" },
        { name = "APIGW_TLS_KEY", value = "${local.tls_dir}/tls.key" },
        { name = "APIGW_CONFIG_CACHE", value = "/var/cache/apigw/config.json" },
        { name = "AWS_REGION", value = local.region },
      ]
      portMappings = [
        { containerPort = api.api_port, protocol = "tcp" },
        { containerPort = api.admin_port, protocol = "tcp" },
      ]
      mountPoints = [
        { sourceVolume = "tls", containerPath = local.tls_dir, readOnly = true },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = local.region
          awslogs-stream-prefix = name
        }
      }
    }
  ]

  container_definitions = concat([
    {
      name       = "tls-init"
      image      = local.tls_init_image
      essential  = false
      entryPoint = ["sh", "-ec"]
      command    = [local.tls_init_command]
      mountPoints = [
        { sourceVolume = "tls", containerPath = local.tls_dir, readOnly = false },
      ]
      logConfiguration = local.tls_init_log_configuration
    }
  ], local.gateway_containers)
}
