# =============================================================================
# Live ECS Cluster Infrastructure
# All resources conditional on var.live_enabled (count on the module call)
# Deploys an environment pointing at Stellar pubnet (mainnet) in the same region
# Resource bodies live in modules/ecs-stack; state moves in moved-live.tf.
# =============================================================================

module "live" {
  source = "./modules/ecs-stack"
  count  = var.live_enabled ? 1 : 0

  env         = "live"
  name_prefix = local.name_prefix

  vpc_cidr        = var.live_vpc_cidr
  certificate_arn = var.live_certificate_arn

  rds_engine_version   = var.rds_engine_version
  rds_instance_class   = var.live_rds_instance_class
  redis_engine_version = var.redis_engine_version
  redis_node_type      = var.live_redis_node_type

  jwt_secret = var.live_jwt_secret

  sqs_visibility_timeout_seconds = var.sqs_visibility_timeout_seconds
  sqs_max_receive_count          = var.sqs_max_receive_count

  container_image        = "${aws_ecr_repository.bridge.repository_url}:${var.container_image_tag}"
  container_architecture = var.container_architecture

  server_cpu           = var.live_server_cpu
  server_memory        = var.live_server_memory
  worker_cpu           = var.live_worker_cpu
  worker_memory        = var.live_worker_memory
  server_desired_count = var.live_server_desired_count
  worker_desired_count = var.live_worker_desired_count

  aws_region       = var.aws_region
  ses_from_address = var.ses_from_address
  fcm_project_id   = var.fcm_project_id

  stellar = {
    network            = "pubnet"
    horizon_url        = "https://horizon.stellar.org"
    rpc_url            = "https://soroban-rpc.stellar.org"
    network_passphrase = "Public Global Stellar Network ; September 2015"
    debug_mode         = "false"
  }

  # --- C3 hardening (full production posture) ---

  # Two AZs: subnets, route tables and NAT gateways fan out (nat_count
  # defaults to az_count = 2, one NAT per AZ — no cross-AZ single point of
  # failure). Also satisfies the >= 2-subnet requirement that real
  # aws_db_subnet_group / aws_lb applies enforce, and gives RDS Multi-AZ and
  # ElastiCache Multi-AZ below a second AZ to land in.
  az_count = 2

  # Staged Redis TLS: flip to "required" ONLY after the bridge image with
  # rediss:// support (workstream A5) is deployed to this stack.
  transit_encryption_mode = "preferred"
  # AUTH token + REDIS_URL moves from plain task env to a Secrets Manager
  # secret (rediss://:<token>@<endpoint>:6379). NOTE: the secret URL is
  # rediss://, so the task definitions this creates already need the A5
  # bridge image (TLS-capable redis client) when they roll out.
  redis_auth_enabled = true
  # Primary + replica; the module derives automatic_failover_enabled and
  # multi_az_enabled = true from this.
  redis_num_cache_clusters = 2

  sns_kms_master_key_id   = "alias/aws/sns"
  sqs_managed_sse_enabled = true # SSE-SQS; NOT alias/aws/sqs (breaks SNS delivery)

  rds_deletion_protection     = true
  rds_backup_retention_period = 30
  rds_multi_az                = true
  rds_skip_final_snapshot     = false # final snapshot "<name_prefix>-db-live-final"

  # Scope the task role's SES statement to the verified sender identity.
  ses_identity_arn = var.ses_from_address != "" ? aws_ses_email_identity.sender[0].arn : ""

  alb_access_logs_enabled = true
  alarms_enabled          = true # DLQ depth + unhealthy targets
  extended_alarms_enabled = true # ALB 5xx + RDS CPU + RDS free storage

  # --- WS4 hardening ---
  # (waf_enabled is deliberately default-ON in the module — not set here.)

  # REJECT-only VPC flow logs (denied-connection forensics at low volume).
  flow_logs_enabled = true

  # RDS storage autoscaling: grow the 20 GiB base online up to 100 GiB.
  rds_max_allocated_storage = 100

  # maxmemory-policy = noeviction + timeout = 0 — see the fail-closed
  # rationale on aws_elasticache_parameter_group.this in the module.
  redis_parameter_group_enabled = true

  # CPU target-tracking: server 2 -> up to 4 tasks (server_max_count default),
  # worker pinned at 2 (worker_max_count default = desired) until SQS-depth
  # scaling lands.
  autoscaling_enabled = true

  # Route alarm/ok actions to the shared ops topic when it exists (ops.tf).
  alarm_sns_topic_arn = var.ops_alerts_enabled ? aws_sns_topic.ops[0].arn : ""
}
