# =============================================================================
# CloudWatch alarms (opt-in; defaults off = pre-C3 behavior).
#
#   var.alarms_enabled          — baseline: worker DLQ depth, unhealthy ALB
#                                 targets (testnet + live)
#   var.extended_alarms_enabled — adds ALB 5xx, RDS CPU, RDS free storage
#                                 (live only)
#
# Every alarm routes alarm_actions + ok_actions to var.alarm_sns_topic_arn
# when the root wires one in (../../ops.tf topic via var.ops_alerts_enabled);
# "" keeps the legacy console-/EventBridge-only behavior.
# =============================================================================

locals {
  # [] when no topic is configured — CloudWatch rejects empty-string ARNs.
  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}

# --- Baseline (var.alarms_enabled) ---

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  count = var.alarms_enabled ? 1 : 0

  alarm_name          = "${var.name_prefix}-${var.env}-worker-dlq-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "${var.env} worker DLQ has messages — jobs exhausted their SQS redeliveries"
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions

  dimensions = {
    QueueName = aws_sqs_queue.worker_dlq[0].name
  }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  count = var.alarms_enabled ? 1 : 0

  alarm_name          = "${var.name_prefix}-${var.env}-unhealthy-targets"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "${var.env} server target group has unhealthy targets"
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions

  dimensions = {
    LoadBalancer = aws_lb.this[0].arn_suffix
    TargetGroup  = aws_lb_target_group.server[0].arn_suffix
  }
}

# --- Extended (var.extended_alarms_enabled) ---

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  count = var.extended_alarms_enabled ? 1 : 0

  alarm_name          = "${var.name_prefix}-${var.env}-alb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Elevated 5xx rate from the ${var.env} ALB (potential exploitation or degradation)"
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions

  dimensions = {
    LoadBalancer = aws_lb.this[0].arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  count = var.extended_alarms_enabled ? 1 : 0

  alarm_name          = "${var.name_prefix}-${var.env}-rds-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "${var.env} database CPU above 80% for 15 minutes"
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.this[0].identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_free_storage" {
  count = var.extended_alarms_enabled ? 1 : 0

  alarm_name          = "${var.name_prefix}-${var.env}-rds-free-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 2147483648 # 2 GiB of the 20 GiB allocation
  alarm_description   = "${var.env} database free storage below 2 GiB"
  treat_missing_data  = "notBreaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.this[0].identifier
  }
}
