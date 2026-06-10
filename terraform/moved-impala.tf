# =============================================================================
# State moves: pre-module impala resources -> module.impala[0].
# One moved{} block per resource (generated from `grep '^resource' impala.tf`
# at the commit that introduced the module). Former count-gated singletons
# move instance-level and DROP the [0] index (the module body has no count);
# count=2 and per-service for_each resources move as whole resources, which
# preserves their instance keys ([0]/[1], "impala-api"/"impala-admin") exactly.
#
# OPERATOR RUNBOOK (README.md "Zero-destroy migration runbook"):
#   1. Back up state first: `terraform state pull > pre-migration.tfstate`.
#   2. Review the plan log: it must show ONLY moves and end with
#      `Plan: 0 to add, 0 to change, 0 to destroy`. Any add/change/destroy
#      means a drifted argument or address mismatch — STOP and diff it.
#   3. Only then approve the gated apply.
# Keep these moved{} blocks for at least one release after the migration has
# been applied to every state (testnet/live/impala), then remove in a cleanup PR.
# =============================================================================

moved {
  from = aws_vpc.impala[0]
  to   = module.impala[0].aws_vpc.this
}

moved {
  from = aws_internet_gateway.impala[0]
  to   = module.impala[0].aws_internet_gateway.this
}

moved {
  from = aws_subnet.impala_public
  to   = module.impala[0].aws_subnet.public
}

moved {
  from = aws_route_table.impala_public[0]
  to   = module.impala[0].aws_route_table.public
}

moved {
  from = aws_route_table_association.impala_public
  to   = module.impala[0].aws_route_table_association.public
}

moved {
  from = aws_security_group.impala_alb
  to   = module.impala[0].aws_security_group.alb
}

moved {
  from = aws_security_group.impala_tasks
  to   = module.impala[0].aws_security_group.tasks
}

moved {
  from = aws_lb.impala
  to   = module.impala[0].aws_lb.this
}

moved {
  from = aws_lb_target_group.impala
  to   = module.impala[0].aws_lb_target_group.this
}

moved {
  from = aws_lb_listener.impala_https
  to   = module.impala[0].aws_lb_listener.https
}

moved {
  from = aws_lb_listener.impala_http_redirect
  to   = module.impala[0].aws_lb_listener.http_redirect
}

moved {
  from = aws_iam_role.impala_execution[0]
  to   = module.impala[0].aws_iam_role.execution
}

moved {
  from = aws_iam_role_policy_attachment.impala_execution_managed[0]
  to   = module.impala[0].aws_iam_role_policy_attachment.execution_managed
}

moved {
  from = aws_cloudwatch_log_group.impala
  to   = module.impala[0].aws_cloudwatch_log_group.this
}

moved {
  from = aws_ecs_cluster.impala[0]
  to   = module.impala[0].aws_ecs_cluster.this
}

moved {
  from = aws_ecs_task_definition.impala
  to   = module.impala[0].aws_ecs_task_definition.this
}

moved {
  from = aws_ecs_service.impala
  to   = module.impala[0].aws_ecs_service.this
}

moved {
  from = aws_kms_key.impala_logs[0]
  to   = module.impala[0].aws_kms_key.logs
}

moved {
  from = aws_kms_alias.impala_logs[0]
  to   = module.impala[0].aws_kms_alias.logs
}

moved {
  from = aws_s3_bucket.impala_alb_logs[0]
  to   = module.impala[0].aws_s3_bucket.alb_logs
}

moved {
  from = aws_s3_bucket_public_access_block.impala_alb_logs[0]
  to   = module.impala[0].aws_s3_bucket_public_access_block.alb_logs
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.impala_alb_logs[0]
  to   = module.impala[0].aws_s3_bucket_server_side_encryption_configuration.alb_logs
}

moved {
  from = aws_s3_bucket_lifecycle_configuration.impala_alb_logs[0]
  to   = module.impala[0].aws_s3_bucket_lifecycle_configuration.alb_logs
}

moved {
  from = aws_s3_bucket_policy.impala_alb_logs[0]
  to   = module.impala[0].aws_s3_bucket_policy.alb_logs
}

moved {
  from = aws_cloudwatch_log_group.impala_vpc_flow_logs[0]
  to   = module.impala[0].aws_cloudwatch_log_group.vpc_flow_logs
}

moved {
  from = aws_iam_role.impala_flow_logs[0]
  to   = module.impala[0].aws_iam_role.flow_logs
}

moved {
  from = aws_iam_role_policy.impala_flow_logs[0]
  to   = module.impala[0].aws_iam_role_policy.flow_logs
}

moved {
  from = aws_flow_log.impala[0]
  to   = module.impala[0].aws_flow_log.this
}

moved {
  from = aws_cloudwatch_metric_alarm.impala_alb_5xx
  to   = module.impala[0].aws_cloudwatch_metric_alarm.alb_5xx
}

moved {
  from = aws_cloudwatch_metric_alarm.impala_unhealthy_targets
  to   = module.impala[0].aws_cloudwatch_metric_alarm.unhealthy_targets
}

