# =============================================================================
# State moves: pre-module testnet resources -> module.testnet[0].
# One moved{} block per resource (generated from `grep '^resource' testnet.tf`
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
  from = aws_vpc.testnet[0]
  to   = module.testnet[0].aws_vpc.this[0]
}

moved {
  from = aws_subnet.testnet_public[0]
  to   = module.testnet[0].aws_subnet.public[0]
}

moved {
  from = aws_subnet.testnet_private[0]
  to   = module.testnet[0].aws_subnet.private[0]
}

moved {
  from = aws_internet_gateway.testnet[0]
  to   = module.testnet[0].aws_internet_gateway.this[0]
}

moved {
  from = aws_eip.testnet_nat[0]
  to   = module.testnet[0].aws_eip.nat[0]
}

moved {
  from = aws_nat_gateway.testnet[0]
  to   = module.testnet[0].aws_nat_gateway.this[0]
}

moved {
  from = aws_route_table.testnet_public[0]
  to   = module.testnet[0].aws_route_table.public[0]
}

moved {
  from = aws_route_table_association.testnet_public[0]
  to   = module.testnet[0].aws_route_table_association.public[0]
}

moved {
  from = aws_route_table.testnet_private[0]
  to   = module.testnet[0].aws_route_table.private[0]
}

moved {
  from = aws_route_table_association.testnet_private[0]
  to   = module.testnet[0].aws_route_table_association.private[0]
}

moved {
  from = aws_security_group.testnet_alb[0]
  to   = module.testnet[0].aws_security_group.alb[0]
}

moved {
  from = aws_security_group.testnet_ecs_tasks[0]
  to   = module.testnet[0].aws_security_group.ecs_tasks[0]
}

moved {
  from = aws_security_group.testnet_rds[0]
  to   = module.testnet[0].aws_security_group.rds[0]
}

moved {
  from = aws_security_group.testnet_redis[0]
  to   = module.testnet[0].aws_security_group.redis[0]
}

moved {
  from = aws_lb.testnet[0]
  to   = module.testnet[0].aws_lb.this[0]
}

moved {
  from = aws_lb_target_group.testnet_server[0]
  to   = module.testnet[0].aws_lb_target_group.server[0]
}

moved {
  from = aws_lb_listener.testnet_http[0]
  to   = module.testnet[0].aws_lb_listener.http[0]
}

moved {
  from = aws_lb_listener.testnet_https[0]
  to   = module.testnet[0].aws_lb_listener.https[0]
}

moved {
  from = aws_elasticache_subnet_group.testnet[0]
  to   = module.testnet[0].aws_elasticache_subnet_group.this[0]
}

moved {
  from = aws_elasticache_replication_group.testnet[0]
  to   = module.testnet[0].aws_elasticache_replication_group.this[0]
}

moved {
  from = random_password.testnet_rds_password[0]
  to   = module.testnet[0].random_password.rds_password[0]
}

moved {
  from = aws_kms_key.testnet_rds[0]
  to   = module.testnet[0].aws_kms_key.rds[0]
}

moved {
  from = aws_db_subnet_group.testnet[0]
  to   = module.testnet[0].aws_db_subnet_group.this[0]
}

moved {
  from = aws_db_instance.testnet[0]
  to   = module.testnet[0].aws_db_instance.this[0]
}

moved {
  from = aws_sns_topic.testnet_jobs[0]
  to   = module.testnet[0].aws_sns_topic.jobs[0]
}

moved {
  from = aws_sqs_queue.testnet_worker_dlq[0]
  to   = module.testnet[0].aws_sqs_queue.worker_dlq[0]
}

moved {
  from = aws_sqs_queue.testnet_worker[0]
  to   = module.testnet[0].aws_sqs_queue.worker[0]
}

moved {
  from = aws_sns_topic_subscription.testnet_worker[0]
  to   = module.testnet[0].aws_sns_topic_subscription.worker[0]
}

moved {
  from = aws_sqs_queue_policy.testnet_worker[0]
  to   = module.testnet[0].aws_sqs_queue_policy.worker[0]
}

moved {
  from = aws_secretsmanager_secret.testnet_database_url[0]
  to   = module.testnet[0].aws_secretsmanager_secret.database_url[0]
}

moved {
  from = aws_secretsmanager_secret_version.testnet_database_url[0]
  to   = module.testnet[0].aws_secretsmanager_secret_version.database_url[0]
}

moved {
  from = aws_secretsmanager_secret.testnet_jwt_secret[0]
  to   = module.testnet[0].aws_secretsmanager_secret.jwt_secret[0]
}

moved {
  from = aws_secretsmanager_secret_version.testnet_jwt_secret[0]
  to   = module.testnet[0].aws_secretsmanager_secret_version.jwt_secret[0]
}

moved {
  from = aws_iam_role.testnet_ecs_task_execution[0]
  to   = module.testnet[0].aws_iam_role.ecs_task_execution[0]
}

moved {
  from = aws_iam_role_policy_attachment.testnet_ecs_task_execution[0]
  to   = module.testnet[0].aws_iam_role_policy_attachment.ecs_task_execution[0]
}

moved {
  from = aws_iam_role_policy.testnet_execution_secrets[0]
  to   = module.testnet[0].aws_iam_role_policy.execution_secrets[0]
}

moved {
  from = aws_iam_role.testnet_ecs_task[0]
  to   = module.testnet[0].aws_iam_role.ecs_task[0]
}

moved {
  from = aws_iam_role_policy.testnet_ecs_task_permissions[0]
  to   = module.testnet[0].aws_iam_role_policy.ecs_task_permissions[0]
}

moved {
  from = aws_cloudwatch_log_group.testnet_server[0]
  to   = module.testnet[0].aws_cloudwatch_log_group.server[0]
}

moved {
  from = aws_cloudwatch_log_group.testnet_worker[0]
  to   = module.testnet[0].aws_cloudwatch_log_group.worker[0]
}

moved {
  from = aws_ecs_cluster.testnet[0]
  to   = module.testnet[0].aws_ecs_cluster.this[0]
}

moved {
  from = aws_ecs_task_definition.testnet_server[0]
  to   = module.testnet[0].aws_ecs_task_definition.server[0]
}

moved {
  from = aws_ecs_task_definition.testnet_worker[0]
  to   = module.testnet[0].aws_ecs_task_definition.worker[0]
}

moved {
  from = aws_ecs_service.testnet_server[0]
  to   = module.testnet[0].aws_ecs_service.server[0]
}

moved {
  from = aws_ecs_service.testnet_worker[0]
  to   = module.testnet[0].aws_ecs_service.worker[0]
}

