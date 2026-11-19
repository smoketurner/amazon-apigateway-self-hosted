resource "aws_ecr_repository" "this" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group_name
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
  policy_arn = local.execution_policy_arn
}

# The task role is the identity apigw's AWS credential chain resolves to.
resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume_tasks.json
}

resource "aws_iam_role_policy" "gateway" {
  name   = "gateway"
  role   = aws_iam_role.task.id
  policy = var.gateway_policy_json
}

resource "aws_iam_role_policy" "additional" {
  for_each = var.additional_apis

  name   = "gateway-${each.key}"
  role   = aws_iam_role.task.id
  policy = each.value.gateway_policy_json
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

resource "aws_vpc_security_group_ingress_rule" "additional" {
  for_each = local.additional_ingress

  security_group_id = aws_security_group.this.id
  description       = "apigw listener of an additional API"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
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
  cpu                      = local.task_cpu
  memory                   = local.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  volume {
    name = "tls"
  }

  container_definitions = jsonencode(local.container_definitions)
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
