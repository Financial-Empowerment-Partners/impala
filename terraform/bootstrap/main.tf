# =============================================================================
# Bootstrap: creates the remote-state backend infrastructure for the main root
# module (an encrypted, versioned S3 state bucket + a DynamoDB lock table).
#
# Run ONCE, before the first `terraform init -migrate-state` of the main root:
#   cd terraform/bootstrap
#   terraform init
#   terraform apply -var="state_bucket_name=impala-tfstate-<account-id>"
#
# This root keeps LOCAL state (bootstrap/terraform.tfstate, covered by the repo
# .gitignore *.tfstate rule). It does not need the S3 backend itself — that would
# be the chicken-and-egg problem this module exists to solve.
# =============================================================================

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region for the state bucket + lock table"
  type        = string
  default     = "us-east-1"
}

variable "state_bucket_name" {
  description = "Globally-unique S3 bucket name for Terraform state"
  type        = string
}

variable "lock_table_name" {
  description = "DynamoDB table name for state locking"
  type        = string
  default     = "impala-tflock"
}

resource "aws_s3_bucket" "tfstate" {
  bucket = var.state_bucket_name
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "tflock" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}

output "state_bucket" {
  description = "Use as -backend-config=\"bucket=...\" for the main root"
  value       = aws_s3_bucket.tfstate.id
}

output "lock_table" {
  description = "Use as -backend-config=\"dynamodb_table=...\" for the main root"
  value       = aws_dynamodb_table.tflock.name
}
