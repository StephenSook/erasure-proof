# ECR repos for the two images. Immutable tags: deploys reference SHA tags, never :latest.

resource "aws_ecr_repository" "api" {
  name                 = "${local.name}-api"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true # rehearsal teardown removes images with the repo
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "cryptod" {
  name                 = "${local.name}-cryptod"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "mcpserver" {
  name                 = "${local.name}-mcpserver"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}

# Keep only the last 5 images per repo (storage pennies, but no unbounded growth).
locals {
  ecr_expiry_policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "expire all but the newest 5"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name
  policy     = local.ecr_expiry_policy
}

resource "aws_ecr_lifecycle_policy" "cryptod" {
  repository = aws_ecr_repository.cryptod.name
  policy     = local.ecr_expiry_policy
}

resource "aws_ecr_lifecycle_policy" "mcpserver" {
  repository = aws_ecr_repository.mcpserver.name
  policy     = local.ecr_expiry_policy
}
