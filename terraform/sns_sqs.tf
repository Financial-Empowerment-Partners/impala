# --- SNS Topic for job dispatch ---

resource "aws_sns_topic" "jobs" {
  name = "${local.name_prefix}-jobs"

  tags = {
    Name = "${local.name_prefix}-jobs"
  }
}

# --- SQS Dead Letter Queue ---

resource "aws_sqs_queue" "worker_dlq" {
  name                      = "${local.name_prefix}-worker-dlq"
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Name = "${local.name_prefix}-worker-dlq"
  }
}

# --- SQS Worker Queue ---

resource "aws_sqs_queue" "worker" {
  name                       = "${local.name_prefix}-worker"
  visibility_timeout_seconds = var.sqs_visibility_timeout_seconds
  message_retention_seconds  = 345600 # 4 days
  receive_wait_time_seconds  = 20     # long polling

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.worker_dlq.arn
    maxReceiveCount     = var.sqs_max_receive_count
  })

  tags = {
    Name = "${local.name_prefix}-worker"
  }
}

# --- SNS -> SQS Subscription ---

resource "aws_sns_topic_subscription" "worker" {
  topic_arn = aws_sns_topic.jobs.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.worker.arn
}

# --- SQS Queue Policy: allow SNS to send messages ---

resource "aws_sqs_queue_policy" "worker" {
  queue_url = aws_sqs_queue.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSNSSend"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.worker.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.jobs.arn
          }
        }
      }
    ]
  })
}
