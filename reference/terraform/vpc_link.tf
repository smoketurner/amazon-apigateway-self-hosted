resource "aws_lb" "vpc_link" {
  count = var.enable_vpc_link ? 1 : 0

  name               = "${var.name_prefix}-vpc-link"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.vpc_link_subnet_ids

  lifecycle {
    precondition {
      condition     = var.vpc_id != null && length(var.vpc_link_subnet_ids) > 0
      error_message = "enable_vpc_link requires vpc_id and vpc_link_subnet_ids."
    }
  }
}

resource "aws_lb_target_group" "vpc_link" {
  count = var.enable_vpc_link ? 1 : 0

  name        = "${var.name_prefix}-vpc-link"
  port        = 80
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = var.vpc_id
}

resource "aws_lb_target_group_attachment" "vpc_link" {
  for_each = var.enable_vpc_link ? toset(var.vpc_link_target_ips) : toset([])

  target_group_arn = aws_lb_target_group.vpc_link[0].arn
  target_id        = each.value
  port             = 80
}

resource "aws_lb_listener" "vpc_link" {
  count = var.enable_vpc_link ? 1 : 0

  load_balancer_arn = aws_lb.vpc_link[0].arn
  port              = 80
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vpc_link[0].arn
  }
}

resource "aws_api_gateway_vpc_link" "reference" {
  count = var.enable_vpc_link ? 1 : 0

  name        = "${var.name_prefix}-vpc-link"
  target_arns = [aws_lb.vpc_link[0].arn]
}
