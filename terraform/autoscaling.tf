# =============================================================================
# Server Auto Scaling
# =============================================================================

resource "aws_appautoscaling_target" "server" {
  max_capacity       = var.server_max_count
  min_capacity       = var.server_min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.server.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

# --- Server: CPU target tracking (scale out at 85%) ---

resource "aws_appautoscaling_policy" "server_cpu" {
  name               = "${local.name_prefix}-server-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.server.resource_id
  scalable_dimension = aws_appautoscaling_target.server.scalable_dimension
  service_namespace  = aws_appautoscaling_target.server.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value       = var.autoscaling_cpu_threshold
    scale_in_cooldown  = var.autoscaling_scale_in_cooldown
    scale_out_cooldown = var.autoscaling_scale_out_cooldown
  }
}

# --- Server: Memory target tracking (scale out at 90%) ---

resource "aws_appautoscaling_policy" "server_memory" {
  name               = "${local.name_prefix}-server-memory"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.server.resource_id
  scalable_dimension = aws_appautoscaling_target.server.scalable_dimension
  service_namespace  = aws_appautoscaling_target.server.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }

    target_value       = var.autoscaling_memory_threshold
    scale_in_cooldown  = var.autoscaling_scale_in_cooldown
    scale_out_cooldown = var.autoscaling_scale_out_cooldown
  }
}

# --- Server: ALB response time target tracking (scale out at 250ms) ---

resource "aws_appautoscaling_policy" "server_latency" {
  name               = "${local.name_prefix}-server-latency"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.server.resource_id
  scalable_dimension = aws_appautoscaling_target.server.scalable_dimension
  service_namespace  = aws_appautoscaling_target.server.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.main.arn_suffix}/${aws_lb_target_group.server.arn_suffix}"
    }

    # ALBRequestCountPerTarget doesn't directly measure latency, so we use a
    # custom metric policy below for the actual latency threshold. This policy
    # handles request-count-based scaling as a complementary signal.
    target_value       = 1000
    scale_in_cooldown  = var.autoscaling_scale_in_cooldown
    scale_out_cooldown = var.autoscaling_scale_out_cooldown
  }
}

# --- Server: Step scaling policy for ALB latency (TargetResponseTime) ---
# TargetResponseTime is not a predefined metric for target tracking, so we
# use a step scaling policy driven by a CloudWatch alarm.

resource "aws_appautoscaling_policy" "server_latency_scale_out" {
  name               = "${local.name_prefix}-server-latency-out"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.server.resource_id
  scalable_dimension = aws_appautoscaling_target.server.scalable_dimension
  service_namespace  = aws_appautoscaling_target.server.service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = var.autoscaling_scale_out_cooldown
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_lower_bound = 0
      metric_interval_upper_bound = 100 # 250ms–350ms: add 1 task
      scaling_adjustment          = 1
    }

    step_adjustment {
      metric_interval_lower_bound = 100 # >350ms: add 2 tasks
      scaling_adjustment          = 2
    }
  }
}

resource "aws_appautoscaling_policy" "server_latency_scale_in" {
  name               = "${local.name_prefix}-server-latency-in"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.server.resource_id
  scalable_dimension = aws_appautoscaling_target.server.scalable_dimension
  service_namespace  = aws_appautoscaling_target.server.service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = var.autoscaling_scale_in_cooldown
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment          = -1
    }
  }
}

# CloudWatch alarm: ALB target response time > threshold
resource "aws_cloudwatch_metric_alarm" "server_high_latency" {
  alarm_name          = "${local.name_prefix}-server-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = var.autoscaling_latency_threshold_ms / 1000 # Convert ms to seconds
  alarm_description   = "Server ALB response time exceeds ${var.autoscaling_latency_threshold_ms}ms"
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.server.arn_suffix
  }

  alarm_actions = compact([
    aws_appautoscaling_policy.server_latency_scale_out.arn,
    var.alert_email != "" ? aws_sns_topic.alerts[0].arn : "",
  ])

  ok_actions = [
    aws_appautoscaling_policy.server_latency_scale_in.arn,
  ]
}

# CloudWatch alarm: ALB target response time recovery (below threshold)
resource "aws_cloudwatch_metric_alarm" "server_latency_ok" {
  alarm_name          = "${local.name_prefix}-server-latency-ok"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = var.autoscaling_latency_threshold_ms / 1000 * 0.8 # 80% of threshold for hysteresis
  alarm_description   = "Server ALB response time recovered below ${var.autoscaling_latency_threshold_ms * 0.8}ms"
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.main.arn_suffix
    TargetGroup  = aws_lb_target_group.server.arn_suffix
  }

  alarm_actions = [
    aws_appautoscaling_policy.server_latency_scale_in.arn,
  ]
}

# =============================================================================
# Worker Auto Scaling
# =============================================================================

resource "aws_appautoscaling_target" "worker" {
  max_capacity       = var.worker_max_count
  min_capacity       = var.worker_min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.worker.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

# --- Worker: CPU target tracking (scale out at 85%) ---

resource "aws_appautoscaling_policy" "worker_cpu" {
  name               = "${local.name_prefix}-worker-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.worker.resource_id
  scalable_dimension = aws_appautoscaling_target.worker.scalable_dimension
  service_namespace  = aws_appautoscaling_target.worker.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value       = var.autoscaling_cpu_threshold
    scale_in_cooldown  = var.autoscaling_scale_in_cooldown
    scale_out_cooldown = var.autoscaling_scale_out_cooldown
  }
}

# --- Worker: Memory target tracking (scale out at 90%) ---

resource "aws_appautoscaling_policy" "worker_memory" {
  name               = "${local.name_prefix}-worker-memory"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.worker.resource_id
  scalable_dimension = aws_appautoscaling_target.worker.scalable_dimension
  service_namespace  = aws_appautoscaling_target.worker.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }

    target_value       = var.autoscaling_memory_threshold
    scale_in_cooldown  = var.autoscaling_scale_in_cooldown
    scale_out_cooldown = var.autoscaling_scale_out_cooldown
  }
}

# --- Worker: SQS queue depth step scaling ---
# Scale workers based on the number of messages visible in the queue.

resource "aws_appautoscaling_policy" "worker_queue_scale_out" {
  name               = "${local.name_prefix}-worker-queue-out"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.worker.resource_id
  scalable_dimension = aws_appautoscaling_target.worker.scalable_dimension
  service_namespace  = aws_appautoscaling_target.worker.service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = var.autoscaling_scale_out_cooldown
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_lower_bound = 0
      metric_interval_upper_bound = 100
      scaling_adjustment          = 1
    }

    step_adjustment {
      metric_interval_lower_bound = 100
      scaling_adjustment          = 2
    }
  }
}

resource "aws_appautoscaling_policy" "worker_queue_scale_in" {
  name               = "${local.name_prefix}-worker-queue-in"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.worker.resource_id
  scalable_dimension = aws_appautoscaling_target.worker.scalable_dimension
  service_namespace  = aws_appautoscaling_target.worker.service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = var.autoscaling_scale_in_cooldown
    metric_aggregation_type = "Average"

    step_adjustment {
      metric_interval_upper_bound = 0
      scaling_adjustment          = -1
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "worker_queue_depth_high" {
  alarm_name          = "${local.name_prefix}-worker-queue-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Average"
  threshold           = 10
  alarm_description   = "SQS worker queue has >10 visible messages"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.worker.name
  }

  alarm_actions = compact([
    aws_appautoscaling_policy.worker_queue_scale_out.arn,
    var.alert_email != "" ? aws_sns_topic.alerts[0].arn : "",
  ])

  ok_actions = [
    aws_appautoscaling_policy.worker_queue_scale_in.arn,
  ]
}
