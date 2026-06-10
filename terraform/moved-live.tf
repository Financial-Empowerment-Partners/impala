# =============================================================================
# State moves: pre-module live resources -> module.live[0].
# One moved{} block per resource (generated from `grep '^resource' live.tf`
# at the commit that introduced the module); inner singletons keep their [0]
# index because the module keeps literal `count = 1`.
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
  from = aws_vpc.live[0]
  to   = module.live[0].aws_vpc.this[0]
}

moved {
  from = aws_subnet.live_public[0]
  to   = module.live[0].aws_subnet.public[0]
}

moved {
  from = aws_subnet.live_private[0]
  to   = module.live[0].aws_subnet.private[0]
}

moved {
  from = aws_internet_gateway.live[0]
  to   = module.live[0].aws_internet_gateway.this[0]
}

moved {
  from = aws_eip.live_nat[0]
  to   = module.live[0].aws_eip.nat[0]
}

moved {
  from = aws_nat_gateway.live[0]
  to   = module.live[0].aws_nat_gateway.this[0]
}

moved {
  from = aws_route_table.live_public[0]
  to   = module.live[0].aws_route_table.public[0]
}

moved {
  from = aws_route_table_association.live_public[0]
  to   = module.live[0].aws_route_table_association.public[0]
}

moved {
  from = aws_route_table.live_private[0]
  to   = module.live[0].aws_route_table.private[0]
}

moved {
  from = aws_route_table_association.live_private[0]
  to   = module.live[0].aws_route_table_association.private[0]
}

moved {
  from = aws_security_group.live_alb[0]
  to   = module.live[0].aws_security_group.alb[0]
}

moved {
  from = aws_security_group.live_ecs_tasks[0]
  to   = module.live[0].aws_security_group.ecs_tasks[0]
}

moved {
  from = aws_security_group.live_rds[0]
  to   = module.live[0].aws_security_group.rds[0]
}

moved {
  from = aws_security_group.live_redis[0]
  to   = module.live[0].aws_security_group.redis[0]
}

moved {
  from = aws_lb.live[0]
  to   = module.live[0].aws_lb.this[0]
}

moved {
  from = aws_lb_target_group.live_server[0]
  to   = module.live[0].aws_lb_target_group.server[0]
}

moved {
  from = aws_lb_listener.live_http[0]
  to   = module.live[0].aws_lb_listener.http[0]
}

moved {
  from = aws_lb_listener.live_https[0]
  to   = module.live[0].aws_lb_listener.https[0]
}

moved {
  from = aws_elasticache_subnet_group.live[0]
  to   = module.live[0].aws_elasticache_subnet_group.this[0]
}

moved {
  from = aws_elasticache_replication_group.live[0]
  to   = module.live[0].aws_elasticache_replication_group.this[0]
}

moved {
  from = random_password.live_rds_password[0]
  to   = module.live[0].random_password.rds_password[0]
}

moved {
  from = aws_kms_key.live_rds[0]
  to   = module.live[0].aws_kms_key.rds[0]
}

moved {
  from = aws_db_subnet_group.live[0]
  to   = module.live[0].aws_db_subnet_group.this[0]
}

moved {
  from = aws_db_instance.live[0]
  to   = module.live[0].aws_db_instance.this[0]
}

moved {
  from = aws_sns_topic.live_jobs[0]
  to   = module.live[0].aws_sns_topic.jobs[0]
}

moved {
  from = aws_sqs_queue.live_worker_dlq[0]
  to   = module.live[0].aws_sqs_queue.worker_dlq[0]
}

moved {
  from = aws_sqs_queue.live_worker[0]
  to   = module.live[0].aws_sqs_queue.worker[0]
}

moved {
  from = aws_sns_topic_subscription.live_worker[0]
  to   = module.live[0].aws_sns_topic_subscription.worker[0]
}

moved {
  from = aws_sqs_queue_policy.live_worker[0]
  to   = module.live[0].aws_sqs_queue_policy.worker[0]
}

moved {
  from = aws_secretsmanager_secret.live_database_url[0]
  to   = module.live[0].aws_secretsmanager_secret.database_url[0]
}

moved {
  from = aws_secretsmanager_secret_version.live_database_url[0]
  to   = module.live[0].aws_secretsmanager_secret_version.database_url[0]
}

moved {
  from = aws_secretsmanager_secret.live_jwt_secret[0]
  to   = module.live[0].aws_secretsmanager_secret.jwt_secret[0]
}

moved {
  from = aws_secretsmanager_secret_version.live_jwt_secret[0]
  to   = module.live[0].aws_secretsmanager_secret_version.jwt_secret[0]
}

moved {
  from = aws_iam_role.live_ecs_task_execution[0]
  to   = module.live[0].aws_iam_role.ecs_task_execution[0]
}

moved {
  from = aws_iam_role_policy_attachment.live_ecs_task_execution[0]
  to   = module.live[0].aws_iam_role_policy_attachment.ecs_task_execution[0]
}

moved {
  from = aws_iam_role_policy.live_execution_secrets[0]
  to   = module.live[0].aws_iam_role_policy.execution_secrets[0]
}

moved {
  from = aws_iam_role.live_ecs_task[0]
  to   = module.live[0].aws_iam_role.ecs_task[0]
}

moved {
  from = aws_iam_role_policy.live_ecs_task_permissions[0]
  to   = module.live[0].aws_iam_role_policy.ecs_task_permissions[0]
}

moved {
  from = aws_cloudwatch_log_group.live_server[0]
  to   = module.live[0].aws_cloudwatch_log_group.server[0]
}

moved {
  from = aws_cloudwatch_log_group.live_worker[0]
  to   = module.live[0].aws_cloudwatch_log_group.worker[0]
}

moved {
  from = aws_ecs_cluster.live[0]
  to   = module.live[0].aws_ecs_cluster.this[0]
}

moved {
  from = aws_ecs_task_definition.live_server[0]
  to   = module.live[0].aws_ecs_task_definition.server[0]
}

moved {
  from = aws_ecs_task_definition.live_worker[0]
  to   = module.live[0].aws_ecs_task_definition.worker[0]
}

moved {
  from = aws_ecs_service.live_server[0]
  to   = module.live[0].aws_ecs_service.server[0]
}

moved {
  from = aws_ecs_service.live_worker[0]
  to   = module.live[0].aws_ecs_service.worker[0]
}

