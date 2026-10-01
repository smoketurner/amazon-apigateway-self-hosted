resource "aws_lb" "this" {
  name               = local.name
  internal           = true
  load_balancer_type = "network"
  subnets            = var.subnet_ids
}

resource "aws_lb_target_group" "this" {
  name        = local.name
  port        = local.target_port
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = var.vpc_id
}

resource "aws_lb_target_group_attachment" "this" {
  for_each = toset(var.target_ips)

  target_group_arn = aws_lb_target_group.this.arn
  target_id        = each.value
  port             = local.target_port
}

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn
  port              = local.target_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_api_gateway_vpc_link" "this" {
  name        = local.name
  target_arns = [aws_lb.this.arn]
}
