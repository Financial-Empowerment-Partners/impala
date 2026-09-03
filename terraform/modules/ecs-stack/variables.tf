# Inputs for one bridge stack. The root module keeps its original
# per-stack variable surface (var.testnet_* / var.live_*) and maps it onto
# these; defaults therefore live at the root, not here.

variable "env" {
  description = "Stack name suffix used in resource names, tags and descriptions (testnet or live)"
  type        = string
}

variable "name_prefix" {
  description = "Shared resource name prefix (root local.name_prefix = project_name-environment)"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the stack VPC"
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener (empty disables the listener)"
  type        = string

  # A certificate-less stack serves the bridge over plain HTTP (see the http
  # listener in main.tf) — acceptable only for testnet/dev. A pubnet (mainnet,
  # real-money) stack must never expose credentials and custodial operations
  # over cleartext, so refuse the combination outright.
  validation {
    condition     = var.stellar.network != "pubnet" || var.certificate_arn != ""
    error_message = "certificate_arn is required for a pubnet (mainnet) stack: without it the ALB serves the custodial API over plain HTTP. Plain HTTP is allowed only for non-production (testnet/dev) stacks."
  }
}

variable "rds_engine_version" {
  description = "PostgreSQL engine version"
  type        = string
}

variable "rds_instance_class" {
  description = "RDS instance class for the stack database"
  type        = string
}

variable "redis_engine_version" {
  description = "Redis engine version"
  type        = string
}

variable "redis_node_type" {
  description = "ElastiCache node type for the stack Redis"
  type        = string
}

variable "jwt_secret" {
  description = "JWT signing secret for the stack impala-bridge"
  type        = string
  sensitive   = true
}

variable "sqs_visibility_timeout_seconds" {
  description = "SQS visibility timeout for worker messages"
  type        = number
}

variable "sqs_max_receive_count" {
  description = "Max receives before message goes to DLQ"
  type        = number
}

variable "container_image" {
  description = "Full image reference for both task definitions (repository_url:tag)"
  type        = string
}

variable "container_architecture" {
  description = "CPU architecture for ECS tasks: X86_64 or ARM64 (Graviton)"
  type        = string
}

variable "server_cpu" {
  description = "CPU units for the server task"
  type        = number
}

variable "server_memory" {
  description = "Memory in MiB for the server task"
  type        = number
}

variable "worker_cpu" {
  description = "CPU units for the worker task"
  type        = number
}

variable "worker_memory" {
  description = "Memory in MiB for the worker task"
  type        = number
}

variable "server_desired_count" {
  description = "Desired number of server tasks"
  type        = number
}

variable "worker_desired_count" {
  description = "Desired number of worker tasks"
  type        = number
}

variable "aws_region" {
  description = "AWS region (env var + awslogs option in the task definitions)"
  type        = string
}

variable "ses_from_address" {
  description = "SES verified sender email address for notifications (optional)"
  type        = string
}

variable "fcm_project_id" {
  description = "Firebase project ID for push notifications (optional)"
  type        = string
}

# =============================================================================
# C3 hardening knobs. Every default below preserves the pre-hardening (C2)
# behavior, so a module call that sets none of these still plans 0/0/0 against
# the pre-refactor state. The per-stack values live in ../../testnet.tf and
# ../../live.tf.
# =============================================================================

variable "az_count" {
  description = <<-EOT
    Number of AZs to spread the public/private subnets (and their route
    tables) across. Default 1 = the historical single-subnet topology.
    NOTE: a real apply of aws_db_subnet_group (needs subnets in >= 2 AZs)
    and aws_lb (needs >= 2 public subnets) REJECTS az_count = 1 — see the
    networking section in main.tf.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.az_count >= 1
    error_message = "az_count must be at least 1."
  }
}

variable "nat_count" {
  description = <<-EOT
    Number of NAT gateways (and EIPs). null = one per AZ (az_count).
    Decoupled from az_count so a lean stack can run 2 subnets with a single
    NAT gateway (e.g. testnet az_count = 2, nat_count = 1).
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.nat_count == null ? true : (var.nat_count >= 1 && var.nat_count <= var.az_count)
    error_message = "nat_count must be between 1 and az_count (or null for one NAT per AZ)."
  }
}

variable "transit_encryption_mode" {
  description = <<-EOT
    ElastiCache in-transit TLS rollout stage. "" keeps the legacy plaintext
    behavior; "preferred" enables TLS while still accepting plaintext
    clients; "required" enforces TLS-only. Flip a stack to "required" ONLY
    after the bridge image with rediss:// support (workstream A5) is
    deployed, otherwise its plaintext connections are cut off.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = contains(["", "preferred", "required"], var.transit_encryption_mode)
    error_message = "transit_encryption_mode must be \"\", \"preferred\" or \"required\"."
  }
}

variable "redis_auth_enabled" {
  description = <<-EOT
    Enable a Redis AUTH token (random_password) and move REDIS_URL from a
    plain container environment variable to a Secrets Manager secret holding
    rediss://:<token>@<primary_endpoint>:6379.
  EOT
  type        = bool
  default     = false

  validation {
    condition     = !var.redis_auth_enabled || var.transit_encryption_mode != ""
    error_message = "redis_auth_enabled requires transit_encryption_mode to be set — ElastiCache only accepts AUTH tokens on TLS-enabled replication groups."
  }
}

variable "redis_num_cache_clusters" {
  description = <<-EOT
    Number of cache clusters (primary + replicas) in the replication group.
    Values > 1 also derive automatic_failover_enabled and multi_az_enabled
    = true in main.tf (the trio is only valid together). Multi-AZ placement
    additionally needs az_count >= 2 so the subnet group spans two AZs.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.redis_num_cache_clusters >= 1
    error_message = "redis_num_cache_clusters must be at least 1."
  }
}

variable "sns_kms_master_key_id" {
  description = "KMS key id/alias for SNS topic encryption (\"alias/aws/sns\"). \"\" keeps the legacy unencrypted topic."
  type        = string
  default     = ""
}

variable "sqs_managed_sse_enabled" {
  description = <<-EOT
    Enable SSE-SQS (SQS-owned encryption keys) on the worker queue + DLQ.
    null leaves the attribute unmanaged (legacy behavior). Deliberately a
    bool for SSE-SQS rather than a kms_master_key_id knob: SNS cannot
    deliver to a queue encrypted with the AWS-managed "alias/aws/sqs" key
    (SNS gets no kms:GenerateDataKey grant on that key's service-scoped
    policy), so the SNS->SQS fan-out would silently drop every job.
  EOT
  type        = bool
  default     = null
}

variable "ses_identity_arn" {
  description = <<-EOT
    ARN of the verified SES identity used as ses_from_address; scopes the
    task role's ses:SendEmail/SendRawEmail statement. "" falls back to
    Resource = "*" (legacy). The statement is omitted entirely when
    ses_from_address is "".
  EOT
  type        = string
  default     = ""
}

variable "rds_deletion_protection" {
  description = "Protect the stack database from terraform destroy / console deletion."
  type        = bool
  default     = false
}

variable "rds_backup_retention_period" {
  description = "Days of automated RDS backups to retain (1 = legacy minimum)."
  type        = number
  default     = 1
}

variable "rds_multi_az" {
  description = "Run the stack database with a synchronous standby in a second AZ (requires az_count >= 2)."
  type        = bool
  default     = false
}

variable "rds_skip_final_snapshot" {
  description = "Skip the final snapshot on database deletion. false also sets final_snapshot_identifier = \"<name_prefix>-db-<env>-final\"."
  type        = bool
  default     = true
}

variable "alb_access_logs_enabled" {
  description = "Ship ALB access logs to a module-managed S3 bucket (see alb-logs.tf)."
  type        = bool
  default     = false
}

variable "alarms_enabled" {
  description = "Baseline CloudWatch alarms: worker DLQ depth, unhealthy ALB targets (see alarms.tf)."
  type        = bool
  default     = false
}

variable "extended_alarms_enabled" {
  description = "Extended CloudWatch alarms on top of the baseline: ALB 5xx, RDS CPU, RDS free storage (see alarms.tf)."
  type        = bool
  default     = false
}

# =============================================================================
# WS4 hardening knobs (terraform stream). Defaults preserve pre-WS4 behavior
# EXCEPT waf_enabled (deliberately default-ON — see waf.tf) and
# rds_storage_type (gp3 default = an in-place gp2->gp3 storage modification on
# the first apply). Per-stack values live in ../../testnet.tf and ../../live.tf.
# =============================================================================

variable "waf_enabled" {
  description = <<-EOT
    Attach a WAFv2 web ACL (AWS managed Common/KnownBadInputs/SQLi rule groups
    + a per-IP rate-based block rule) to the stack ALB. Deliberately default-ON
    (breaks the zero-diff module convention per the WS4 spec): the next apply
    adds ~USD 5/mo per ACL + ~USD 1/mo per rule + per-request charges to every
    stack. Set false per stack to opt out; see waf.tf for the false-positive
    notes on the managed groups.
  EOT
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "Per-IP request ceiling for the WAF rate-based block rule (requests per 5-minute rolling window)."
  type        = number
  default     = 2000

  validation {
    condition     = var.waf_rate_limit >= 100
    error_message = "waf_rate_limit must be at least 100 (WAFv2 rate-based statement minimum)."
  }
}

variable "flow_logs_enabled" {
  description = <<-EOT
    Ship REJECT-traffic VPC flow logs to a 30-day CloudWatch log group (see
    flow-logs.tf). REJECT-only keeps volume/cost low while preserving the
    denied-connection forensics signal; modules/impala-stack logs ALL.
  EOT
  type        = bool
  default     = false
}

variable "rds_max_allocated_storage" {
  description = <<-EOT
    Upper bound in GiB for RDS storage autoscaling. 0 disables autoscaling
    (legacy behavior); > 0 lets RDS grow the 20 GiB base allocation online up
    to this cap instead of hard-stopping on a full disk.
  EOT
  type        = number
  default     = 0

  validation {
    condition     = var.rds_max_allocated_storage == 0 || var.rds_max_allocated_storage >= 20
    error_message = "rds_max_allocated_storage must be 0 (autoscaling off) or >= the 20 GiB base allocation."
  }
}

variable "rds_storage_type" {
  description = <<-EOT
    RDS storage type. The gp3 default is a deliberate default-change: the
    first apply after it migrates existing gp2 storage IN-PLACE (online, but
    the instance passes through "storage-optimization" and storage cannot be
    modified again for ~6 hours afterwards).
  EOT
  type        = string
  default     = "gp3"

  validation {
    condition     = contains(["gp2", "gp3"], var.rds_storage_type)
    error_message = "rds_storage_type must be \"gp2\" or \"gp3\"."
  }
}

variable "rds_force_ssl_enabled" {
  description = <<-EOT
    Attach a parameter group with rds.force_ssl = 1 (TLS-only PostgreSQL) and
    append ?sslmode=require to the DATABASE_URL secret. Bridge-compatible
    without code changes (sqlx tls-rustls-aws-lc-rs; sslmode=require needs no
    CA bundle). ROLLOUT: the parameter-group swap reboots the DB
    (apply_immediately = true; rds.force_ssl is a static parameter) and the
    new secret value only reaches tasks on the next ECS deployment — apply,
    force a new deployment, verify connectivity, testnet before live.
  EOT
  type        = bool
  default     = false
}

variable "autoscaling_enabled" {
  description = "Enable CPU target-tracking autoscaling for the server and worker ECS services (see autoscaling.tf). Default off = fixed desired_count."
  type        = bool
  default     = false
}

variable "server_max_count" {
  description = "Autoscaling ceiling for server tasks (min stays at server_desired_count)."
  type        = number
  default     = 4

  validation {
    condition     = var.server_max_count >= 1
    error_message = "server_max_count must be at least 1."
  }
}

variable "worker_max_count" {
  description = "Autoscaling ceiling for worker tasks (min stays at worker_desired_count)."
  type        = number
  default     = 2

  validation {
    condition     = var.worker_max_count >= 1
    error_message = "worker_max_count must be at least 1."
  }
}

variable "autoscaling_cpu_target" {
  description = "Average service CPU utilization (%) the target-tracking policies hold."
  type        = number
  default     = 60

  validation {
    condition     = var.autoscaling_cpu_target > 0 && var.autoscaling_cpu_target <= 100
    error_message = "autoscaling_cpu_target must be between 1 and 100."
  }
}

variable "alarm_sns_topic_arn" {
  description = <<-EOT
    SNS topic ARN to receive alarm_actions + ok_actions from every stack
    CloudWatch alarm (the root passes the ops.tf topic when
    var.ops_alerts_enabled). "" keeps the legacy console-only alarms.
  EOT
  type        = string
  default     = ""
}

variable "redis_parameter_group_enabled" {
  description = <<-EOT
    Replace default.redis7 with a stack parameter group pinning
    maxmemory-policy = noeviction and timeout = 0 — see the fail-closed
    rationale comment on aws_elasticache_parameter_group.this in main.tf.
    Applies in-place, no replacement/reboot.
  EOT
  type        = bool
  default     = false
}

variable "stellar" {
  description = <<-EOT
    Stellar network selection for the bridge env vars. soroban_contract_id and
    network_passphrase are the slot-7 optionals: omit (null) to drop the env
    var entirely; testnet sets soroban_contract_id (kept even when ""), live
    sets network_passphrase. debug_mode is the string value of DEBUG_MODE.
  EOT
  type = object({
    network             = string
    horizon_url         = string
    rpc_url             = string
    soroban_contract_id = optional(string)
    network_passphrase  = optional(string)
    debug_mode          = string
  })
}

variable "cors_allowed_origins" {
  description = <<-EOT
    CORS_ALLOWED_ORIGINS for the stack's bridge SERVER task: the
    comma-separated admin-UI origins, e.g. "https://admin.example.com".
    null (default) omits the variable entirely — the testnet task
    definition stays byte-identical and the bridge falls back to its
    wildcard default. That default is a STARTUP ERROR on pubnet
    (impala-bridge/src/config.rs validate_cors_policy), so a pubnet stack
    without explicit origins could never become healthy — refused here, the
    same way certificate_arn refuses a pubnet stack without TLS.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.cors_allowed_origins == null || (trimspace(var.cors_allowed_origins) != "" && trimspace(var.cors_allowed_origins) != "*")
    error_message = "cors_allowed_origins must list explicit origins (or be left null); \"*\" and \"\" are not accepted."
  }

  validation {
    condition     = var.stellar.network != "pubnet" || var.cors_allowed_origins != null
    error_message = "cors_allowed_origins is required for a pubnet (mainnet) stack: the bridge exits at startup when CORS_ALLOWED_ORIGINS is unset or \"*\" with STELLAR_NETWORK=pubnet, so the stack could never boot."
  }
}

variable "public_endpoint" {
  description = <<-EOT
    PUBLIC_ENDPOINT for the stack's bridge SERVER task — the externally
    reachable base URL of the API (https://api.<domain>), used by the
    bridge's startup secure-cookie sanity check. null (default) omits the
    variable (zero churn); must be https:// on a pubnet stack.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.public_endpoint == null || can(regex("^https?://[^/\\s]+", var.public_endpoint))
    error_message = "public_endpoint must be an absolute http(s):// URL (or null)."
  }

  validation {
    condition     = var.stellar.network != "pubnet" || var.public_endpoint == null || startswith(var.public_endpoint, "https://")
    error_message = "public_endpoint must be an https:// URL on a pubnet stack (the bridge sets Secure session cookies, which browsers drop on a plain-HTTP endpoint)."
  }
}

variable "extra_environment" {
  description = <<-EOT
    Extra NON-SECRET env entries appended LAST to both task definitions
    (after seed_protection_environment and the CORS/PUBLIC_ENDPOINT slots).
    The root passes var.bridge_extra_environment, whose validation refuses
    names the stacks already manage and secret-looking names; only the name
    shape is re-checked here. [] default = zero container_definitions churn.
  EOT
  type = list(object({
    name  = string
    value = string
  }))
  default = []

  validation {
    condition     = alltrue([for e in var.extra_environment : can(regex("^[A-Z][A-Z0-9_]*$", e.name))])
    error_message = "extra_environment names must be UPPER_SNAKE_CASE environment variable names."
  }
}

variable "seed_protection_environment" {
  description = <<-EOT
    Custodial seed-protection env entries (SEED_PROTECTION_BACKEND,
    KMS_SEED_KEY_ID, VAULT_ADDR, VAULT_TRANSIT_KEY) appended to both task
    definitions — the root builds these in ../../seeds.tf per stack. The
    bridge defaults SEED_PROTECTION_BACKEND to "none" when the var is absent,
    so the [] default preserves both today's runtime behavior AND the
    byte-identical env list (zero container_definitions churn) until the root
    wires a backend.
  EOT
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}
