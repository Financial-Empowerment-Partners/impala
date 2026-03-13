# =============================================================================
# Alert SNS Topic (optional, created only if alert_email is provided)
# =============================================================================

resource "aws_sns_topic" "alerts" {
  count = var.alert_email != "" ? 1 : 0
  name  = "${local.name_prefix}-alerts"

  tags = {
    Name = "${local.name_prefix}-alerts"
  }
}

resource "aws_sns_topic_subscription" "alerts_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# =============================================================================
# Server Service Alarms
# =============================================================================

# CPU utilization alarm
resource "aws_cloudwatch_metric_alarm" "server_cpu_high" {
  alarm_name          = "${local.name_prefix}-server-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = var.autoscaling_cpu_threshold
  alarm_description   = "Server CPU utilization above ${var.autoscaling_cpu_threshold}% for 3 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.server.name
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions    = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

# Memory utilization alarm
resource "aws_cloudwatch_metric_alarm" "server_memory_high" {
  alarm_name          = "${local.name_prefix}-server-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = var.autoscaling_memory_threshold
  alarm_description   = "Server memory utilization above ${var.autoscaling_memory_threshold}% for 3 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.server.name
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions    = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

# Running task count alarm (zero healthy tasks)
resource "aws_cloudwatch_metric_alarm" "server_no_running_tasks" {
  alarm_name          = "${local.name_prefix}-server-no-tasks"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "No healthy server tasks registered with ALB"
  treat_missing_data  = "breaching"

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.server.arn_suffix
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions    = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

# ALB 5xx error rate alarm
resource "aws_cloudwatch_metric_alarm" "server_5xx_errors" {
  alarm_name          = "${local.name_prefix}-server-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Server returning >10 5xx errors per minute"
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.server.arn_suffix
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions    = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

# =============================================================================
# Worker Service Alarms
# =============================================================================

# Worker CPU utilization alarm
resource "aws_cloudwatch_metric_alarm" "worker_cpu_high" {
  alarm_name          = "${local.name_prefix}-worker-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = var.autoscaling_cpu_threshold
  alarm_description   = "Worker CPU utilization above ${var.autoscaling_cpu_threshold}% for 3 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.worker.name
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions    = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

# Worker memory utilization alarm
resource "aws_cloudwatch_metric_alarm" "worker_memory_high" {
  alarm_name          = "${local.name_prefix}-worker-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 60
  statistic           = "Average"
  threshold           = var.autoscaling_memory_threshold
  alarm_description   = "Worker memory utilization above ${var.autoscaling_memory_threshold}% for 3 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.worker.name
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
  ok_actions    = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

# DLQ messages alarm (failed jobs accumulating)
resource "aws_cloudwatch_metric_alarm" "worker_dlq_messages" {
  alarm_name          = "${local.name_prefix}-worker-dlq"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Messages accumulating in worker dead-letter queue"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.worker_dlq.name
  }

  alarm_actions = var.alert_email != "" ? [aws_sns_topic.alerts[0].arn] : []
}

# =============================================================================
# CloudWatch Dashboard
# =============================================================================

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${local.name_prefix}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Row 1: Server service metrics
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6
        properties = {
          title = "Server CPU & Memory"
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", aws_ecs_service.server.name, { stat = "Average", label = "CPU %" }],
            ["AWS/ECS", "MemoryUtilization", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", aws_ecs_service.server.name, { stat = "Average", label = "Memory %" }],
          ]
          yAxis = { left = { min = 0, max = 100 } }
          annotations = {
            horizontal = [
              { value = var.autoscaling_cpu_threshold, label = "CPU threshold", color = "#ff6600" },
              { value = var.autoscaling_memory_threshold, label = "Memory threshold", color = "#cc0000" },
            ]
          }
          period = 60
          region = var.aws_region
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6
        properties = {
          title = "ALB Response Time"
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.main.arn_suffix, "TargetGroup", aws_lb_target_group.server.arn_suffix, { stat = "Average", label = "Avg Response Time" }],
            ["...", { stat = "p99", label = "p99 Response Time" }],
          ]
          annotations = {
            horizontal = [
              { value = var.autoscaling_latency_threshold_ms / 1000, label = "Latency threshold", color = "#ff6600" },
            ]
          }
          period = 60
          region = var.aws_region
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6
        properties = {
          title = "Server Task Count"
          metrics = [
            ["AWS/ApplicationELB", "HealthyHostCount", "LoadBalancer", aws_lb.main.arn_suffix, "TargetGroup", aws_lb_target_group.server.arn_suffix, { stat = "Average", label = "Healthy" }],
            ["AWS/ApplicationELB", "UnHealthyHostCount", "LoadBalancer", aws_lb.main.arn_suffix, "TargetGroup", aws_lb_target_group.server.arn_suffix, { stat = "Average", label = "Unhealthy" }],
          ]
          period = 60
          region = var.aws_region
        }
      },

      # Row 2: ALB traffic + errors, Worker metrics
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        properties = {
          title = "ALB Request Count & Errors"
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.main.arn_suffix, { stat = "Sum", label = "Requests" }],
            ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", aws_lb.main.arn_suffix, { stat = "Sum", label = "5xx Errors", color = "#cc0000" }],
            ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", aws_lb.main.arn_suffix, { stat = "Sum", label = "4xx Errors", color = "#ff9900" }],
          ]
          period = 60
          region = var.aws_region
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        properties = {
          title = "Worker CPU & Memory"
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", aws_ecs_service.worker.name, { stat = "Average", label = "CPU %" }],
            ["AWS/ECS", "MemoryUtilization", "ClusterName", aws_ecs_cluster.main.name, "ServiceName", aws_ecs_service.worker.name, { stat = "Average", label = "Memory %" }],
          ]
          yAxis = { left = { min = 0, max = 100 } }
          annotations = {
            horizontal = [
              { value = var.autoscaling_cpu_threshold, label = "CPU threshold", color = "#ff6600" },
              { value = var.autoscaling_memory_threshold, label = "Memory threshold", color = "#cc0000" },
            ]
          }
          period = 60
          region = var.aws_region
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        properties = {
          title = "SQS Queue Depth"
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", aws_sqs_queue.worker.name, { stat = "Average", label = "Visible" }],
            ["AWS/SQS", "ApproximateNumberOfMessagesNotVisible", "QueueName", aws_sqs_queue.worker.name, { stat = "Average", label = "In Flight" }],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", aws_sqs_queue.worker_dlq.name, { stat = "Average", label = "DLQ", color = "#cc0000" }],
          ]
          period = 60
          region = var.aws_region
        }
      },
    ]
  })
}
