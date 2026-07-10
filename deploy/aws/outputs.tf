output "cloudfront_url" {
  description = "The judge-facing URL."
  value       = "https://${aws_cloudfront_distribution.main.domain_name}"
}

output "alb_dns" {
  description = "Direct ALB DNS (403s without the origin-verify header; debugging only)."
  value       = aws_lb.api.dns_name
}

output "ecr_api" {
  value = aws_ecr_repository.api.repository_url
}

output "ecr_cryptod" {
  value = aws_ecr_repository.cryptod.repository_url
}

output "web_bucket" {
  description = "aws s3 sync web/dist/ s3://<this>/ then invalidate CloudFront."
  value       = aws_s3_bucket.web.bucket
}

output "task_role_arns" {
  description = "The three-principal split (plus the assume-only base)."
  value = {
    svc_base  = aws_iam_role.svc_base.arn
    eraser    = aws_iam_role.eraser.arn
    anchor    = aws_iam_role.anchor.arn
    inference = aws_iam_role.inference.arn
  }
}
