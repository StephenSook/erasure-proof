# Network: the default VPC's public subnets, no NAT gateway (saves ~$35/mo). Tasks get public
# IPs; their security group accepts traffic ONLY from the ALB's security group, and the ALB
# accepts ONLY the CloudFront-injected verification header (enforced at the listener rule).

data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  name       = var.project
}

resource "aws_security_group" "alb" {
  name_prefix = "${local.name}-alb-"
  description = "ALB: HTTP from anywhere (CloudFront fronts it; the origin-verify header gates real traffic)"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "task" {
  name_prefix = "${local.name}-task-"
  description = "Fargate task: api port reachable ONLY from the ALB"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # CockroachDB Cloud, KMS, S3, Bedrock, ECR pulls
  }
}
