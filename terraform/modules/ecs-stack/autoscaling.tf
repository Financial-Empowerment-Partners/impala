# =============================================================================
# ECS service autoscaling (opt-in via var.autoscaling_enabled; default off =
# fixed desired_count, the pre-WS4 behavior).
#
# Target-tracking on average service CPU: target var.autoscaling_cpu_target,
# scale-out cooldown 60 s (react fast to load), scale-in cooldown 300 s
# (avoid flapping). min stays at the stack's desired count — autoscaling only
# ever ADDS capacity; max is server_max_count / worker_max_count. Both
# services already set lifecycle { ignore_changes = [desired_count] } in
# main.tf, which is required for coexistence with Application Auto Scaling.
#
# The worker scales on CPU only: SQS-queue-depth scaling needs a custom
# metric (backlog per task) + step policy — flagged follow-up, not built here.
# =============================================================================

resource "aws_appautoscaling_target" "server" {
  count = var.autoscaling_enabled ? 1 : 0

  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.this[0].name}/${aws_ecs_service.server[0].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.server_desired_count
  max_capacity       = var.server_max_count
}

resource "aws_appautoscaling_policy" "server_cpu" {
  count = var.autoscaling_enabled ? 1 : 0

  name               = "${var.name_prefix}-${var.env}-server-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.server[0].service_namespace
  resource_id        = aws_appautoscaling_target.server[0].resource_id
  scalable_dimension = aws_appautoscaling_target.server[0].scalable_dimension

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value       = var.autoscaling_cpu_target
    scale_out_cooldown = 60
    scale_in_cooldown  = 300
  }
}

resource "aws_appautoscaling_target" "worker" {
  count = var.autoscaling_enabled ? 1 : 0

  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.this[0].name}/${aws_ecs_service.worker[0].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.worker_desired_count
  max_capacity       = var.worker_max_count
}

resource "aws_appautoscaling_policy" "worker_cpu" {
  count = var.autoscaling_enabled ? 1 : 0

  name               = "${var.name_prefix}-${var.env}-worker-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.worker[0].service_namespace
  resource_id        = aws_appautoscaling_target.worker[0].resource_id
  scalable_dimension = aws_appautoscaling_target.worker[0].scalable_dimension

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value       = var.autoscaling_cpu_target
    scale_out_cooldown = 60
    scale_in_cooldown  = 300
  }
}
