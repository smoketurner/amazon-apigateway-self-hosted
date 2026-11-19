resource "aws_ecr_repository" "this" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${local.name}"
  retention_in_days = var.log_retention_days
}

# The execution role lets ECS pull the image and write the task's logs. It is
# not available to the gateway process.
resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.assume_tasks.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The task role is the identity apigw's AWS credential chain resolves to.
resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume_tasks.json
}

resource "aws_iam_role_policy" "gateway" {
  name   = "gateway"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.gateway.json
}

resource "aws_security_group" "this" {
  name        = local.name
  description = "apigw test gateway: API and admin ports from the allowed addresses"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "api" {
  for_each = toset(var.allowed_cidrs)

  security_group_id = aws_security_group.this.id
  description       = "apigw API listener"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.api_port
  to_port           = local.api_port
}

resource "aws_vpc_security_group_ingress_rule" "admin" {
  for_each = toset(var.allowed_cidrs)

  security_group_id = aws_security_group.this.id
  description       = "apigw admin listener"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = local.admin_port
  to_port           = local.admin_port
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.this.id
  description       = "AWS APIs, integrations, and identity providers"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_ecs_cluster" "this" {
  name = local.name
}

resource "aws_ecs_task_definition" "this" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  volume {
    name = "tls"
  }

  container_definitions = jsonencode([
    {
      name       = "tls-init"
      image      = "public.ecr.aws/docker/library/alpine:3.24"
      essential  = false
      entryPoint = ["sh", "-ec"]
      command    = [local.tls_init_command]
      mountPoints = [
        { sourceVolume = "tls", containerPath = local.tls_dir, readOnly = false },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "tls-init"
        }
      }
    },
    {
      name      = "apigw"
      image     = "${aws_ecr_repository.this.repository_url}:${var.image_tag}"
      essential = true
      dependsOn = [
        { containerName = "tls-init", condition = "SUCCESS" },
      ]
      # Above the 30 s connection drain that follows SIGTERM.
      stopTimeout = 45
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
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = local.region
          awslogs-stream-prefix = "apigw"
        }
      }
    },
  ])
}

resource "aws_ecs_service" "this" {
  name            = local.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.this.id]
    assign_public_ip = true
  }
}
