# =============================================================================
# VPC flow logs (opt-in via var.flow_logs_enabled; default off = pre-WS4
# behavior, enabled in both ../../testnet.tf and ../../live.tf).
#
# REJECT traffic only — the denied-connection forensics signal at a fraction
# of the volume/cost of ALL (modules/impala-stack logs ALL on its much
# smaller VPC). Pattern copied from modules/impala-stack/main.tf minus the
# KMS CMK on the log group: CloudWatch's default at-rest encryption is a LOW
# trivy finding, below the HIGH/CRITICAL CI gate — CMK encryption is a
# flagged follow-up, and the stack's other log groups (server/worker) are
# uncustomized too.
# =============================================================================

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.flow_logs_enabled ? 1 : 0

  name              = "/aws/vpc/${var.name_prefix}-${var.env}-flow-logs"
  retention_in_days = 30
}

resource "aws_iam_role" "flow_logs" {
  count = var.flow_logs_enabled ? 1 : 0

  name = "${var.name_prefix}-${var.env}-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.flow_logs_enabled ? 1 : 0

  name = "${var.name_prefix}-${var.env}-flow-logs-write"
  role = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      # Scoped to the flow-logs group; ":*" covers its log streams.
      Resource = "${aws_cloudwatch_log_group.flow_logs[0].arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  count = var.flow_logs_enabled ? 1 : 0

  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn
  traffic_type    = "REJECT"
  vpc_id          = aws_vpc.this[0].id

  tags = {
    Name = "${var.name_prefix}-${var.env}-flow-logs"
  }
}
