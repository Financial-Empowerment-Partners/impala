# =============================================================================
# S3 ALB Access Logs Bucket
# =============================================================================

data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket" "alb_logs" {
  bucket = "${local.name_prefix}-alb-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${local.name_prefix}-alb-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

# =============================================================================
# S3 Backup Buckets with Cross-Region Replication
# =============================================================================

# --- Primary Region Backup Bucket ---

resource "aws_s3_bucket" "backups" {
  bucket = "${local.name_prefix}-backups-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${local.name_prefix}-backups"
  }
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- DR Region Backup Bucket (replication target) ---

resource "aws_s3_bucket" "backups_dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  bucket = "${local.name_prefix}-backups-dr-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${local.name_prefix}-backups-dr"
    Role = "disaster-recovery"
  }
}

resource "aws_s3_bucket_versioning" "backups_dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  bucket = aws_s3_bucket.backups_dr[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups_dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  bucket = aws_s3_bucket.backups_dr[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backups_dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  bucket = aws_s3_bucket.backups_dr[0].id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backups_dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  bucket = aws_s3_bucket.backups_dr[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Cross-Region Replication ---

resource "aws_iam_role" "s3_replication" {
  count = var.dr_enabled ? 1 : 0
  name  = "${local.name_prefix}-s3-replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "s3_replication" {
  count = var.dr_enabled ? 1 : 0
  name  = "${local.name_prefix}-s3-replication"
  role  = aws_iam_role.s3_replication[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
        ]
        Resource = aws_s3_bucket.backups.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
        ]
        Resource = "${aws_s3_bucket.backups.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
        ]
        Resource = "${aws_s3_bucket.backups_dr[0].arn}/*"
      },
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "backups" {
  count = var.dr_enabled ? 1 : 0

  depends_on = [aws_s3_bucket_versioning.backups]

  role   = aws_iam_role.s3_replication[0].arn
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "cross-region-replication"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.backups_dr[0].arn
      storage_class = "STANDARD_IA"
    }
  }
}
