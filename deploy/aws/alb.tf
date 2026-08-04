# ALB in front of the Fargate api. HTTP-only between CloudFront and the ALB: with no custom
# domain there is no ACM cert an ALB hostname can present, so the origin leg is plain HTTP and
# the viewer leg (browser -> CloudFront) is HTTPS on the default *.cloudfront.net cert. Stated
# honestly in the runbook; the upgrade path is a custom domain + ACM. The origin-verify header
# (random secret, injected by CloudFront, required by the listener rule) keeps the ALB from
# being used directly.

resource "random_password" "origin_verify" {
  length  = 32
  special = false
}

resource "aws_lb" "api" {
  name               = "${local.name}-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.public.ids
  idle_timeout       = 300 # SSE streams on /api/*
}

resource "aws_lb_target_group" "api" {
  name        = "${local.name}-api"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default.id

  health_check {
    path                = "/healthz"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.api.arn
  port              = 80
  protocol          = "HTTP"

  # Default: refuse anything that did not come through CloudFront.
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Use the CloudFront URL."
      status_code  = "403"
    }
  }
}

resource "aws_lb_listener_rule" "origin_verified" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 10

  condition {
    http_header {
      http_header_name = "X-Origin-Verify"
      values           = [random_password.origin_verify.result]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# The judge-connectable forensics MCP server rides the same task on 8082. Its target-group health
# probe uses the token-exempt /mcp/health path; every real MCP request additionally carries the
# judge bearer, checked inside the container.
resource "aws_lb_target_group" "mcp" {
  name        = "${local.name}-mcp"
  port        = 8082
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default.id

  health_check {
    path                = "/mcp/health"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener_rule" "mcp_origin_verified" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 5 # more specific than the catch-all api rule; both require the origin header

  condition {
    path_pattern {
      values = ["/mcp", "/mcp/*"]
    }
  }
  condition {
    http_header {
      http_header_name = "X-Origin-Verify"
      values           = [random_password.origin_verify.result]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mcp.arn
  }
}
