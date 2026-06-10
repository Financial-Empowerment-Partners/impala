# =============================================================================
# Ops alerting — one shared SNS topic that every stack's CloudWatch alarms
# notify (opt-in via var.ops_alerts_enabled; default off = pre-WS4 behavior).
# The per-stack module calls thread its ARN in as alarm_sns_topic_arn
# (testnet.tf / live.tf / impala.tf).
# =============================================================================

# Customer-managed key instead of the AWS-managed "alias/aws/sns" used by the
# per-stack jobs topics: CloudWatch's service principal gets no
# kms:GenerateDataKey/kms:Decrypt grant on the AWS-managed key's fixed policy,
# so alarm notifications published to a topic encrypted with it are silently
# dropped — the same failure class as the SNS->SQS "alias/aws/sqs" note in
# modules/ecs-stack/main.tf. (The jobs topics are unaffected: their publisher
# is the bridge task, an account IAM principal going via SNS.)
resource "aws_kms_key" "ops" {
  count = var.ops_alerts_enabled ? 1 : 0

  description             = "Encrypts the ${local.name_prefix} ops-alerts SNS topic"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "${local.name_prefix}-ops-alerts-key-policy"
    Statement = [
      {
        Sid       = "EnableRootAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchAlarms"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-ops-alerts-kms"
  }
}

resource "aws_kms_alias" "ops" {
  count = var.ops_alerts_enabled ? 1 : 0

  name          = "alias/${local.name_prefix}-ops-alerts"
  target_key_id = aws_kms_key.ops[0].key_id
}

resource "aws_sns_topic" "ops" {
  count = var.ops_alerts_enabled ? 1 : 0

  name              = "${local.name_prefix}-ops-alerts"
  kms_master_key_id = aws_kms_key.ops[0].id

  tags = {
    Name = "${local.name_prefix}-ops-alerts"
  }
}

# Email endpoints require MANUAL confirmation: AWS mails a confirmation link
# to the address and the subscription sits in "pending confirmation" (no
# delivery) until the recipient clicks it — terraform cannot confirm it and
# the resource stays unconfirmed in state. Re-request from the SNS console if
# the mail is lost.
resource "aws_sns_topic_subscription" "ops_email" {
  count = var.ops_alerts_enabled && var.ops_alert_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.ops[0].arn
  protocol  = "email"
  endpoint  = var.ops_alert_email
}
