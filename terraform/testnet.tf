# =============================================================================
# Testnet ECS Cluster Infrastructure
# All resources conditional on var.testnet_enabled (count on the module call)
# Deploys a separate environment pointing at Stellar testnet (same region)
# Resource bodies live in modules/ecs-stack; state moves in moved-testnet.tf.
# =============================================================================

module "testnet" {
  source = "./modules/ecs-stack"
  count  = var.testnet_enabled ? 1 : 0

  env         = "testnet"
  name_prefix = local.name_prefix

  vpc_cidr        = var.testnet_vpc_cidr
  certificate_arn = var.testnet_certificate_arn

  rds_engine_version   = var.rds_engine_version
  rds_instance_class   = var.testnet_rds_instance_class
  redis_engine_version = var.redis_engine_version
  redis_node_type      = var.testnet_redis_node_type

  jwt_secret = var.testnet_jwt_secret

  sqs_visibility_timeout_seconds = var.sqs_visibility_timeout_seconds
  sqs_max_receive_count          = var.sqs_max_receive_count

  container_image        = "${aws_ecr_repository.bridge.repository_url}:${var.container_image_tag}"
  container_architecture = var.container_architecture

  server_cpu           = var.testnet_server_cpu
  server_memory        = var.testnet_server_memory
  worker_cpu           = var.testnet_worker_cpu
  worker_memory        = var.testnet_worker_memory
  server_desired_count = var.testnet_server_desired_count
  worker_desired_count = var.testnet_worker_desired_count

  aws_region       = var.aws_region
  ses_from_address = var.ses_from_address
  fcm_project_id   = var.fcm_project_id

  # Custodial seed protection (seeds.tf): testnet uses its own independent
  # CMK, kept separate from pubnet seeds. Gated on the backend so the default
  # ("none") passes [] and the task definitions stay byte-identical (the
  # bridge already defaults SEED_PROTECTION_BACKEND to "none").
  seed_protection_environment = var.seed_protection_backend == "none" ? [] : local.seed_protection_env_testnet

  stellar = {
    network             = "testnet"
    horizon_url         = "https://horizon-testnet.stellar.org"
    rpc_url             = "https://soroban-testnet.stellar.org"
    soroban_contract_id = var.testnet_soroban_contract_id
    debug_mode          = "true"
  }

  # Optional on testnet (wildcard CORS is allowed there); null defaults keep
  # the task definition byte-identical.
  cors_allowed_origins = var.testnet_cors_allowed_origins
  public_endpoint      = var.testnet_public_endpoint

  # Non-secret operator extras (RESERVE_*, KEY_IMPORT_ENABLED,
  # ADMIN_ACCOUNT_IDS, TRUSTED_PROXY_HOPS, ...), appended last.
  extra_environment = var.bridge_extra_environment

  # --- C3 hardening (free tier — testnet stays lean otherwise) ---

  # Pre-existing topology bug, surfaced as a knob: the historical stack has
  # ONE public + ONE private subnet, which a real apply rejects
  # (aws_db_subnet_group needs subnets in >= 2 AZs; aws_lb needs >= 2 public
  # subnets). If applies have been failing there, uncomment:
  # az_count  = 2 # two subnets per tier
  # nat_count = 1 # ...but keep a single NAT gateway (lean testnet)

  # Staged Redis TLS: flip to "required" ONLY after the bridge image with
  # rediss:// support (workstream A5) is deployed to this stack.
  transit_encryption_mode = "preferred"
  # AUTH token + REDIS_URL moves from plain task env to a Secrets Manager
  # secret (rediss://:<token>@<endpoint>:6379). NOTE: the secret URL is
  # rediss://, so the task definitions this creates already need the A5
  # bridge image (TLS-capable redis client) when they roll out.
  redis_auth_enabled = true

  sns_kms_master_key_id   = "alias/aws/sns"
  sqs_managed_sse_enabled = true # SSE-SQS; NOT alias/aws/sqs (breaks SNS delivery)

  rds_deletion_protection     = true
  rds_backup_retention_period = 14

  # Scope the task role's SES statement to the verified sender identity.
  ses_identity_arn = var.ses_from_address != "" ? aws_ses_email_identity.sender[0].arn : ""

  # Baseline alarms only (DLQ depth + unhealthy targets).
  alarms_enabled = true

  # --- WS4 hardening ---
  # (waf_enabled is deliberately default-ON in the module — not set here.)

  # REJECT-only VPC flow logs (denied-connection forensics at low volume).
  flow_logs_enabled = true

  # ALB access logs to the module-managed S3 bucket (90-day lifecycle) —
  # brings testnet up to the live posture.
  alb_access_logs_enabled = true

  # RDS storage autoscaling: grow the 20 GiB base online up to 100 GiB.
  rds_max_allocated_storage = 100

  # maxmemory-policy = noeviction + timeout = 0 — see the fail-closed
  # rationale on aws_elasticache_parameter_group.this in the module.
  redis_parameter_group_enabled = true

  # Exercise the autoscaling path cheaply: 1 -> 2 server tasks on CPU > 60%
  # (worker_max_count default 2 lets the worker scale 1 -> 2 too).
  autoscaling_enabled = true
  server_max_count    = 2

  # Route alarm/ok actions to the shared ops topic when it exists (ops.tf).
  alarm_sns_topic_arn = var.ops_alerts_enabled ? aws_sns_topic.ops[0].arn : ""
}
