# Remote state backend (S3 + DynamoDB lock). Partial configuration: the bucket,
# key, region and lock table are supplied at `terraform init` time via
# -backend-config flags (CI passes them from repo vars TF_STATE_BUCKET /
# TF_LOCK_TABLE and secrets.AWS_REGION). Create the bucket + table ONCE with the
# bootstrap/ root module before the first `init -migrate-state`. See README.md.
#
# Local checks (fmt/validate) use `terraform init -backend=false`, which ignores
# this block, so no AWS access is needed to validate.
terraform {
  backend "s3" {
    encrypt = true
    # bucket         = "impala-tfstate-<account-id>"   # via -backend-config
    # key            = "impala/terraform.tfstate"      # via -backend-config
    # region         = "us-east-1"                     # via -backend-config
    # dynamodb_table = "impala-tflock"                 # via -backend-config
  }
}
