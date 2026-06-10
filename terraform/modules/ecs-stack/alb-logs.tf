# =============================================================================
# ALB access logs S3 bucket (opt-in via var.alb_access_logs_enabled; wired
# into the dynamic access_logs block on aws_lb.this in main.tf).
# Pattern copied from modules/impala-stack: bucket + public-access block +
# SSE + 90-day lifecycle + ELB service-account bucket policy.
# =============================================================================

# Region-account that writes ALB access logs (module-local so the module
# stays self-contained). Only resolved when the feature is on.
data "aws_elb_service_account" "this" {
  count = var.alb_access_logs_enabled ? 1 : 0
}

resource "aws_s3_bucket" "alb_logs" {
  count = var.alb_access_logs_enabled ? 1 : 0

  # Exact name (not bucket_prefix): "<name_prefix>-alb-logs-<env>" can exceed
  # the 37-char bucket_prefix ceiling, while the 63-char bucket name limit
  # leaves plenty of headroom for realistic project/environment names.
  bucket        = "${var.name_prefix}-alb-logs-${var.env}"
  force_destroy = false

  tags = {
    Name = "${var.name_prefix}-alb-logs-${var.env}"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  count = var.alb_access_logs_enabled ? 1 : 0

  bucket                  = aws_s3_bucket.alb_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ELB access-log delivery only supports SSE-S3 (AES256); the log-delivery
# service rejects SSE-KMS destination buckets, so a CMK is not an option.
#trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  count = var.alb_access_logs_enabled ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      # ALB access-log delivery supports SSE-S3 only (not SSE-KMS).
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  count = var.alb_access_logs_enabled ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    id     = "expire-after-90-days"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  count = var.alb_access_logs_enabled ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowELBToWrite"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_elb_service_account.this[0].id}:root"
      }
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.alb_logs[0].arn}/*"
    }]
  })
}
