# =============================================================================
# Impala cluster — minimal Fargate stack for impala-api and impala-admin.
# All resources conditional on var.impala_enabled (count on the module call).
# Resource bodies live in modules/impala-stack; state moves in moved-impala.tf.
# Requires var.impala_certificate_arn when enabled (HTTPS-only listeners).
# =============================================================================

module "impala" {
  source = "./modules/impala-stack"
  count  = var.impala_enabled ? 1 : 0

  vpc_cidr        = var.impala_vpc_cidr
  certificate_arn = var.impala_certificate_arn

  ecr_repository_urls    = { for k, r in aws_ecr_repository.deploy : k => r.repository_url }
  container_image_tag    = var.container_image_tag
  container_architecture = var.container_architecture

  aws_region = var.aws_region
  account_id = data.aws_caller_identity.current.account_id

  # --- WS4 hardening ---
  # (waf_enabled is deliberately default-ON in the module — not set here.)

  # Route alarm/ok actions to the shared ops topic when it exists (ops.tf).
  alarm_sns_topic_arn = var.ops_alerts_enabled ? aws_sns_topic.ops[0].arn : ""

  # private_tasks_enabled stays default-OFF: moving the tasks off public IPs
  # adds a NAT gateway (~USD 33/mo + data processing) for ECR pulls — an
  # operator cost decision, not flipped here without sign-off. See the
  # blast-radius/cost comment in modules/impala-stack/main.tf.
  # private_tasks_enabled = true
}
