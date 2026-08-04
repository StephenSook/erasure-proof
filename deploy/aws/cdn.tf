# One CloudFront distribution, one URL for judges: the SPA from a private S3 bucket (OAC) as
# the default origin, /api/* forwarded to the ALB. Same-origin means zero CORS and SSE passes.

resource "aws_s3_bucket" "web" {
  bucket        = "${local.name}-web-${local.account_id}"
  force_destroy = true # rehearsal teardown; the SPA bundle is rebuildable from git
}

resource "aws_s3_bucket_public_access_block" "web" {
  bucket                  = aws_s3_bucket.web.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "web" {
  name                              = "${local.name}-web-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_s3_bucket_policy" "web" {
  bucket = aws_s3_bucket.web.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "CloudFrontOACRead"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.web.arn}/*"
      Condition = {
        StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.main.arn }
      }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.web]
}

locals {
  # AWS managed policy ids (stable, documented):
  # CachingOptimized / CachingDisabled / AllViewerExceptHostHeader
  cache_optimized       = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  cache_disabled        = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
  fwd_all_viewer_nohost = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
}

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  comment             = "${local.name}: SPA + /api"
  default_root_object = "index.html"
  price_class         = "PriceClass_100" # NA + EU edges; judges are US-based

  origin {
    origin_id                = "spa"
    domain_name              = aws_s3_bucket.web.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.web.id
  }

  origin {
    origin_id   = "api"
    domain_name = aws_lb.api.dns_name
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only" # no custom domain = no ACM cert on the ALB; see README
      origin_ssl_protocols   = ["TLSv1.2"]
      # The live agent audit runs a multi-round tool loop; 60s is CloudFront's no-quota maximum.
      # The warm endpoint keeps the cold start OUT of this window (the UI holds until warm).
      origin_read_timeout      = 60
      origin_keepalive_timeout = 60
    }
    custom_header {
      name  = "X-Origin-Verify"
      value = random_password.origin_verify.result
    }
  }

  default_cache_behavior {
    target_origin_id       = "spa"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = local.cache_optimized
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = "api"
    viewer_protocol_policy   = "https-only"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = local.cache_disabled
    origin_request_policy_id = local.fwd_all_viewer_nohost
  }

  # The api also serves /memories, /erase, /healthz at the root path space.
  dynamic "ordered_cache_behavior" {
    for_each = ["/memories*", "/erase*", "/healthz*"]
    content {
      path_pattern             = ordered_cache_behavior.value
      target_origin_id         = "api"
      viewer_protocol_policy   = "https-only"
      allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods           = ["GET", "HEAD"]
      cache_policy_id          = local.cache_disabled
      origin_request_policy_id = local.fwd_all_viewer_nohost
    }
  }

  # SPA routing: unknown paths fall through to index.html so /demo, /trust, /proof/:id deep-link.
  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }
  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true # default *.cloudfront.net URL, per Stephen's decision
  }
}
