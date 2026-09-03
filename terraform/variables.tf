variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "impala-bridge"
}

variable "environment" {
  description = "Deployment environment label (e.g. staging, production). Used in resource names; does not control which Stellar network is targeted."
  type        = string
  default     = "staging"
}

# --- Container ---

variable "container_image_tag" {
  description = "ECR image tag to deploy (REQUIRED, no default): a commit SHA, or the stand-up runbooks' prod-<short-sha> / staging-<short-sha>. The repository is IMMUTABLE and CI pushes only per-commit :<sha> manifests, so nothing ever pushes \"latest\" — a service pointed at it can never start."
  type        = string

  validation {
    condition     = trimspace(var.container_image_tag) != "" && var.container_image_tag != "latest"
    error_message = "container_image_tag must name an explicit image tag (commit SHA, prod-<short-sha> or staging-<short-sha>). \"latest\" is refused: CI never pushes it to the immutable ECR repository."
  }
}

variable "container_architecture" {
  description = "CPU architecture for ECS tasks: X86_64 or ARM64 (Graviton)"
  type        = string
  default     = "ARM64"

  validation {
    condition     = contains(["X86_64", "ARM64"], var.container_architecture)
    error_message = "container_architecture must be X86_64 or ARM64"
  }
}

# --- RDS / ElastiCache (shared engine versions) ---

variable "rds_engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "16.4"
}

variable "rds_allocated_storage" {
  description = "Allocated storage in GB for RDS"
  type        = number
  default     = 20
}

variable "rds_skip_final_snapshot" {
  description = "Skip final snapshot on RDS deletion"
  type        = bool
  default     = false
}

# --- ElastiCache ---

variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t3.micro"
}

variable "redis_engine_version" {
  description = "Redis engine version"
  type        = string
  default     = "7.0"
}

# --- SQS (shared knobs across testnet/live worker queues) ---

variable "sqs_visibility_timeout_seconds" {
  description = "SQS visibility timeout for worker messages"
  type        = number
  default     = 300
}

variable "sqs_max_receive_count" {
  description = "Max receives before message goes to DLQ"
  type        = number
  default     = 3
}

# --- Notifications ---

variable "ses_from_address" {
  description = "SES verified sender email address for notifications (optional)"
  type        = string
  default     = ""
}

variable "fcm_project_id" {
  description = "Firebase project ID for push notifications (optional)"
  type        = string
  default     = ""
}

# --- Ops alerting (shared SNS topic for stack CloudWatch alarms — ops.tf) ---

variable "ops_alerts_enabled" {
  description = "Create the ops-alerts SNS topic and route every stack CloudWatch alarm's alarm_actions + ok_actions to it (threaded into the module calls as alarm_sns_topic_arn)."
  type        = bool
  default     = false
}

variable "ops_alert_email" {
  description = "Email address subscribed to the ops-alerts topic. \"\" skips the subscription. Email endpoints need MANUAL confirmation — see ops.tf."
  type        = string
  default     = ""

  validation {
    condition     = var.ops_alert_email == "" || can(regex("^[^@\\s]+@[^@\\s]+$", var.ops_alert_email))
    error_message = "ops_alert_email must be empty or a valid email address."
  }
}

# --- Custodial Stellar seed protection ---

variable "seed_protection_backend" {
  description = "Backend protecting custodial Stellar seeds: none | kms | vault | openbao. 'vault' and 'openbao' share one API-compatible Transit backend."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "kms", "vault", "openbao"], var.seed_protection_backend)
    error_message = "seed_protection_backend must be one of: none, kms, vault, openbao."
  }
}

variable "kms_seed_key" {
  description = "Optional externally-managed KMS key ARN for seed envelope encryption. Empty = create a dedicated key in this stack."
  type        = string
  default     = ""
}

variable "vault_addr" {
  description = "Vault/OpenBao address for the vault|openbao seed-protection backend (e.g. https://vault.internal:8200). The server is external — Terraform does not provision it."
  type        = string
  default     = ""
}

variable "vault_transit_key" {
  description = "Vault/OpenBao Transit key name used to encrypt/decrypt seeds (vault|openbao backend)."
  type        = string
  default     = ""
}

# --- Disaster Recovery ---

variable "dr_enabled" {
  description = "Enable cross-region DR: ECR image replication plus the standby cluster in dr_region (dr.tf) with Route 53 failover when domain_name is set"
  type        = bool
  default     = false
}

variable "dr_region" {
  description = "AWS region for ECR replication target"
  type        = string
  default     = "us-west-2"
}

# =============================================================================
# Testnet stack (Stellar testnet)
# =============================================================================

variable "testnet_enabled" {
  description = "Enable testnet ECS cluster pointed at Stellar testnet"
  type        = bool
  default     = false
}

variable "testnet_vpc_cidr" {
  description = "CIDR block for the testnet VPC"
  type        = string
  default     = "10.2.0.0/16"
}

variable "testnet_server_desired_count" {
  description = "Desired number of server tasks in testnet cluster"
  type        = number
  default     = 1
}

variable "testnet_worker_desired_count" {
  description = "Desired number of worker tasks in testnet cluster"
  type        = number
  default     = 1
}

variable "testnet_server_cpu" {
  description = "CPU units for testnet server task"
  type        = number
  default     = 256
}

variable "testnet_server_memory" {
  description = "Memory in MiB for testnet server task"
  type        = number
  default     = 512
}

variable "testnet_worker_cpu" {
  description = "CPU units for testnet worker task"
  type        = number
  default     = 256
}

variable "testnet_worker_memory" {
  description = "Memory in MiB for testnet worker task"
  type        = number
  default     = 512
}

variable "testnet_rds_instance_class" {
  description = "RDS instance class for testnet database"
  type        = string
  default     = "db.t3.micro"
}

variable "testnet_redis_node_type" {
  description = "ElastiCache node type for testnet Redis"
  type        = string
  default     = "cache.t3.micro"
}

variable "testnet_jwt_secret" {
  description = "JWT signing secret for testnet impala-bridge (must differ from live)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "testnet_soroban_contract_id" {
  description = "Soroban contract ID deployed on Stellar testnet"
  type        = string
  default     = ""
}

variable "testnet_certificate_arn" {
  description = "ACM certificate ARN for testnet HTTPS listener (optional)"
  type        = string
  default     = ""
}

variable "testnet_cors_allowed_origins" {
  description = "CORS_ALLOWED_ORIGINS for the testnet stack's bridge server (explicit origins). null (default) omits the variable — the bridge's wildcard default is allowed on testnet — and keeps the task definition byte-identical."
  type        = string
  default     = null

  validation {
    condition     = var.testnet_cors_allowed_origins == null || (trimspace(var.testnet_cors_allowed_origins) != "" && trimspace(var.testnet_cors_allowed_origins) != "*")
    error_message = "testnet_cors_allowed_origins must list explicit origins (or be left null); \"*\" and \"\" are not accepted."
  }
}

variable "testnet_public_endpoint" {
  description = "PUBLIC_ENDPOINT for the testnet stack's bridge server (https://api.testnet.<domain>). null (default) omits the variable."
  type        = string
  default     = null

  validation {
    condition     = var.testnet_public_endpoint == null || can(regex("^https?://[^/\\s]+", var.testnet_public_endpoint))
    error_message = "testnet_public_endpoint must be an absolute http(s):// URL (or null)."
  }
}

# =============================================================================
# Live stack (Stellar pubnet / mainnet)
# =============================================================================

variable "live_enabled" {
  description = "Enable live ECS cluster pointed at Stellar pubnet"
  type        = bool
  default     = false
}

variable "live_vpc_cidr" {
  description = "CIDR block for the live VPC (must not overlap testnet_vpc_cidr)"
  type        = string
  default     = "10.3.0.0/16"

  validation {
    condition     = var.live_vpc_cidr != var.testnet_vpc_cidr
    error_message = "live_vpc_cidr must not be identical to testnet_vpc_cidr."
  }
}

variable "live_server_desired_count" {
  description = "Desired number of server tasks in live cluster"
  type        = number
  default     = 2
}

variable "live_worker_desired_count" {
  description = "Desired number of worker tasks in live cluster"
  type        = number
  default     = 2
}

variable "live_server_cpu" {
  description = "CPU units for live server task"
  type        = number
  default     = 512
}

variable "live_server_memory" {
  description = "Memory in MiB for live server task"
  type        = number
  default     = 1024
}

variable "live_worker_cpu" {
  description = "CPU units for live worker task"
  type        = number
  default     = 512
}

variable "live_worker_memory" {
  description = "Memory in MiB for live worker task"
  type        = number
  default     = 1024
}

variable "live_rds_instance_class" {
  description = "RDS instance class for live database"
  type        = string
  default     = "db.t3.small"
}

variable "live_redis_node_type" {
  description = "ElastiCache node type for live Redis"
  type        = string
  default     = "cache.t3.small"
}

variable "live_jwt_secret" {
  description = "JWT signing secret for live impala-bridge (must differ from testnet)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "live_certificate_arn" {
  description = "ACM certificate ARN for live HTTPS listener (required when live_enabled = true)"
  type        = string
  default     = ""

  # The live stack is Stellar pubnet — real money. Without a certificate the
  # stack ALB forwards plain HTTP :80 straight to the bridge, putting
  # credentials and custodial operations on the wire in cleartext. Refuse the
  # combination here (the ecs-stack module also refuses any pubnet stack
  # without a certificate).
  validation {
    condition     = !var.live_enabled || var.live_certificate_arn != ""
    error_message = "live_certificate_arn is required when live_enabled = true: the live (mainnet) stack must not serve the custodial API over plain HTTP."
  }
}

variable "live_cors_allowed_origins" {
  description = <<-EOT
    CORS_ALLOWED_ORIGINS for the live stack's bridge server: the
    comma-separated admin-UI origins, e.g. "https://admin.example.com".
    REQUIRED when live_enabled = true — live is pubnet, and the bridge exits
    at startup when CORS_ALLOWED_ORIGINS is unset or "*" with
    STELLAR_NETWORK=pubnet, so without it the stack can never boot (the
    ecs-stack module refuses the combination too, like certificate_arn).
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.live_cors_allowed_origins == null || (trimspace(var.live_cors_allowed_origins) != "" && trimspace(var.live_cors_allowed_origins) != "*")
    error_message = "live_cors_allowed_origins must list explicit origins; \"*\" and \"\" are not accepted."
  }

  validation {
    condition     = !var.live_enabled || var.live_cors_allowed_origins != null
    error_message = "live_cors_allowed_origins is required when live_enabled = true: the live (pubnet) bridge refuses to start with wildcard/unset CORS_ALLOWED_ORIGINS, so the stack could never become healthy."
  }
}

variable "live_public_endpoint" {
  description = "PUBLIC_ENDPOINT for the live stack's bridge server — the externally reachable https://api.<domain> base URL (used by the bridge's secure-cookie sanity check). null (default) omits the variable; must be https:// when set."
  type        = string
  default     = null

  validation {
    condition     = var.live_public_endpoint == null || startswith(var.live_public_endpoint, "https://")
    error_message = "live_public_endpoint must be an https:// URL (or null): the live stack sets Secure session cookies, which browsers drop on a plain-HTTP endpoint."
  }
}

# =============================================================================
# Impala cluster (minimal Fargate stack for impala-api / impala-admin)
# =============================================================================

variable "impala_enabled" {
  description = "Enable the impala ECS cluster (single task per service, public subnets, two ALBs)"
  type        = bool
  default     = false
}

variable "impala_vpc_cidr" {
  description = "CIDR block for the impala VPC (must not overlap testnet_vpc_cidr or live_vpc_cidr)"
  type        = string
  default     = "10.4.0.0/16"

  validation {
    condition     = var.impala_vpc_cidr != var.testnet_vpc_cidr && var.impala_vpc_cidr != var.live_vpc_cidr
    error_message = "impala_vpc_cidr must not be identical to testnet_vpc_cidr or live_vpc_cidr."
  }
}

variable "impala_certificate_arn" {
  description = "ACM certificate ARN for impala ALBs (required when impala_enabled = true; HTTPS-only listener)"
  type        = string
  default     = ""

  validation {
    condition     = var.impala_certificate_arn == "" || can(regex("^arn:aws:acm:", var.impala_certificate_arn))
    error_message = "impala_certificate_arn must be a valid ACM certificate ARN (must start with arn:aws:acm:) or empty."
  }
}

variable "enable_vpc_endpoints" {
  description = "Create VPC endpoints for AWS services to avoid NAT gateway for API traffic"
  type        = bool
  default     = true
}

# =============================================================================
# Primary stack core (restored in the develop merge — both branches' rewrites
# of this file dropped the shared block these clean .tf files reference)
# =============================================================================

variable "jwt_secret" {
  description = "JWT signing secret for the primary impala-bridge (min 32 chars; the bridge refuses to start with a shorter one)"
  type        = string
  sensitive   = true
}

variable "vpc_cidr" {
  description = "CIDR block for the primary VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "Number of AZs for the primary stack's subnets (RDS Multi-AZ needs subnets in >= 2 AZs)"
  type        = number
  default     = 2
}

variable "server_desired_count" {
  description = "Desired number of server tasks in the primary cluster"
  type        = number
  default     = 2
}

variable "worker_desired_count" {
  description = "Desired number of worker tasks in the primary cluster"
  type        = number
  default     = 2
}

variable "server_cpu" {
  description = "CPU units for the primary server task"
  type        = number
  default     = 512
}

variable "server_memory" {
  description = "Memory in MiB for the primary server task"
  type        = number
  default     = 1024
}

variable "worker_cpu" {
  description = "CPU units for the primary worker task"
  type        = number
  default     = 512
}

variable "worker_memory" {
  description = "Memory in MiB for the primary worker task"
  type        = number
  default     = 1024
}

variable "rds_instance_class" {
  description = "RDS instance class for the primary database"
  type        = string
  default     = "db.t3.small"
}

variable "rds_backup_retention_days" {
  description = "Automated RDS backup retention period in days"
  type        = number
  default     = 7
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the primary ALB HTTPS listener (empty = HTTP only; required when environment = \"production\")"
  type        = string
  default     = ""

  # Plain HTTP on the primary ALB is an explicit non-production posture (the
  # default primary stack points at Stellar testnet). .trivyignore's
  # AVD-AWS-0054 entry asserts "Production sets certificate_arn" — this
  # validation makes that assertion enforced instead of aspirational.
  validation {
    condition     = var.environment != "production" || var.certificate_arn != ""
    error_message = "certificate_arn is required when environment = \"production\": a production deployment must not serve the bridge over plain HTTP."
  }

  # Same rule keyed on the network rather than the label: a pubnet (mainnet,
  # real-money) primary stack must never serve the custodial API over
  # cleartext — mirrors the ecs-stack module's pubnet check for live.
  validation {
    condition     = var.stellar_network != "pubnet" || var.certificate_arn != ""
    error_message = "certificate_arn is required when stellar_network = \"pubnet\": the primary (mainnet) bridge must not serve the custodial API over plain HTTP."
  }
}

# --- Auto scaling (primary cluster) ---

variable "server_min_count" {
  description = "Minimum number of server tasks"
  type        = number
  default     = 2
}

variable "server_max_count" {
  description = "Maximum number of server tasks"
  type        = number
  default     = 10
}

variable "worker_min_count" {
  description = "Minimum number of worker tasks"
  type        = number
  default     = 2
}

variable "worker_max_count" {
  description = "Maximum number of worker tasks"
  type        = number
  default     = 10
}

variable "autoscaling_cpu_threshold" {
  description = "Target CPU utilization percentage for service auto scaling"
  type        = number
  default     = 85
}

variable "autoscaling_memory_threshold" {
  description = "Target memory utilization percentage for service auto scaling"
  type        = number
  default     = 90
}

variable "autoscaling_latency_threshold_ms" {
  description = "ALB TargetResponseTime alarm threshold in milliseconds (step scaling)"
  type        = number
  default     = 250
}

variable "autoscaling_scale_out_cooldown" {
  description = "Cooldown in seconds after a scale-out activity"
  type        = number
  default     = 60
}

variable "autoscaling_scale_in_cooldown" {
  description = "Cooldown in seconds after a scale-in activity"
  type        = number
  default     = 300
}

# --- Monitoring / telemetry ---

variable "alert_email" {
  description = "Email address subscribed to the monitoring alerts SNS topic (empty = no alert subscription)"
  type        = string
  default     = ""
}

variable "signoz_endpoint" {
  description = "SigNoz OTLP collector endpoint; when set, an OTEL collector sidecar is added to both services (empty = disabled)"
  type        = string
  default     = ""
}

variable "signoz_access_token" {
  description = "SigNoz ingestion access token for the OTEL collector sidecar"
  type        = string
  sensitive   = true
  default     = ""
}

# --- Stellar network + endpoints (primary bridge; the DR pair in dr.tf
#     inherits all of them) ---

variable "stellar_network" {
  description = <<-EOT
    Stellar network the PRIMARY bridge (ecs.tf server + worker, and the DR
    pair in dr.tf) runs on: "testnet" (default) or "pubnet" (mainnet).
    Injected as STELLAR_NETWORK, which selects the network passphrase the
    bridge signs transactions with. Without it the bridge defaults to
    testnet mode, so pointing stellar_horizon_url / stellar_rpc_url at
    pubnet alone produced a bridge that signed every transaction with the
    testnet passphrase against pubnet Horizon. The URLs must belong to the
    same network (validated below); "pubnet" additionally requires
    certificate_arn (no real money over plain HTTP) and cors_allowed_origins
    (the bridge exits on wildcard CORS with STELLAR_NETWORK=pubnet). The
    toggled testnet/live stacks pin their own network in testnet.tf /
    live.tf.
  EOT
  type        = string
  default     = "testnet"

  validation {
    condition     = contains(["testnet", "pubnet"], var.stellar_network)
    error_message = "stellar_network must be \"testnet\" or \"pubnet\"."
  }

  validation {
    condition     = var.stellar_network != "pubnet" || !(strcontains(var.stellar_horizon_url, "testnet") || strcontains(var.stellar_rpc_url, "testnet"))
    error_message = "stellar_network = \"pubnet\" but stellar_horizon_url / stellar_rpc_url still point at a testnet endpoint (their defaults are the SDF testnet URLs): set both to pubnet endpoints."
  }

  validation {
    condition     = var.stellar_network != "testnet" || !(var.stellar_horizon_url == "https://horizon.stellar.org" || var.stellar_rpc_url == "https://soroban-rpc.stellar.org")
    error_message = "stellar_network is \"testnet\" (the default) but stellar_horizon_url / stellar_rpc_url point at the SDF pubnet endpoints: a testnet-mode bridge signs with the testnet passphrase, which pubnet rejects. Set stellar_network = \"pubnet\"."
  }
}

variable "stellar_horizon_url" {
  description = "Stellar Horizon API URL for the primary bridge (must match stellar_network)"
  type        = string
  default     = "https://horizon-testnet.stellar.org"
}

variable "stellar_rpc_url" {
  description = "Stellar Soroban RPC URL for the primary bridge (must match stellar_network)"
  type        = string
  default     = "https://soroban-testnet.stellar.org"
}

# --- Browser-facing settings (primary bridge + DR; server task only) ---

variable "cors_allowed_origins" {
  description = <<-EOT
    CORS_ALLOWED_ORIGINS for the primary (and DR) bridge server: the
    comma-separated admin-UI origins, e.g. "https://admin.example.com".
    null (default) omits the variable, leaving the bridge's wildcard default
    — which is fine on testnet but a STARTUP ERROR on pubnet, hence the
    validation. Wildcard is never accepted here.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.cors_allowed_origins == null || (trimspace(var.cors_allowed_origins) != "" && trimspace(var.cors_allowed_origins) != "*")
    error_message = "cors_allowed_origins must list explicit origins (or be left null); \"*\" and \"\" are not accepted."
  }

  validation {
    condition     = var.stellar_network != "pubnet" || var.cors_allowed_origins != null
    error_message = "cors_allowed_origins is required when stellar_network = \"pubnet\": the bridge exits at startup when CORS_ALLOWED_ORIGINS is unset or \"*\" on pubnet, so the tasks could never become healthy."
  }
}

variable "public_endpoint" {
  description = <<-EOT
    PUBLIC_ENDPOINT for the primary (and DR) bridge server — the externally
    reachable base URL of the API (https://api.<domain>). The bridge uses it
    for its startup secure-cookie sanity check (a plain-http value with
    Secure cookies is logged as a misconfiguration). null (default) omits
    the variable.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.public_endpoint == null || can(regex("^https?://[^/\\s]+", var.public_endpoint))
    error_message = "public_endpoint must be an absolute http(s):// URL (or null)."
  }

  validation {
    condition     = var.stellar_network != "pubnet" || var.public_endpoint == null || startswith(var.public_endpoint, "https://")
    error_message = "public_endpoint must be an https:// URL when stellar_network = \"pubnet\" (the bridge sets Secure session cookies, which browsers drop on a plain-HTTP endpoint)."
  }
}

# --- DR sizing / failover DNS ---

variable "dr_vpc_cidr" {
  description = "CIDR block for the DR VPC (must not overlap the primary vpc_cidr)"
  type        = string
  default     = "10.1.0.0/16"
}

variable "dr_server_desired_count" {
  description = "Desired number of server tasks in the DR standby cluster"
  type        = number
  default     = 1
}

variable "dr_worker_desired_count" {
  description = "Desired number of worker tasks in the DR standby cluster"
  type        = number
  default     = 1
}

variable "domain_name" {
  description = "Base domain for the Route 53 failover record (api.<domain_name>); empty = no failover DNS"
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID for domain_name"
  type        = string
  default     = ""
}

# =============================================================================
# Extra bridge environment (all stacks)
# =============================================================================

variable "bridge_extra_environment" {
  description = <<-EOT
    Extra NON-SECRET environment entries appended LAST to every bridge task
    definition: the primary server + worker (ecs.tf), the DR pair (dr.tf)
    and both module stacks (testnet.tf / live.tf via extra_environment).
    This is the plumbing for bridge settings that have no dedicated
    Terraform variable — the conversion-reserve wiring (RESERVE_ACCOUNT_ID,
    RESERVE_USDC_ISSUER, RESERVE_USDT0_ISSUER, RESERVE_USDT0_TICKERS, ...),
    KEY_IMPORT_ENABLED, ADMIN_ACCOUNT_IDS, TRUSTED_PROXY_HOPS (1 behind the
    ALB) and the rest of impala-bridge/src/config.rs. Values are PLAINTEXT
    in the task definition, the plan output and state, so secret-looking
    names are refused: credentials go through Secrets Manager + the task
    definition `secrets` block (or the bridge's /admin/keys import path),
    never here. Names Terraform already manages are refused as well —
    duplicate names in an ECS environment list are ambiguous; use the
    dedicated variables (stellar_network, cors_allowed_origins,
    public_endpoint, live_*, testnet_*, ...). Same list for every stack: keep
    per-stack differences (issuers, allowlists) in the per-stack variables
    or split the workspaces.
  EOT
  type = list(object({
    name  = string
    value = string
  }))
  default = []

  validation {
    condition     = alltrue([for e in var.bridge_extra_environment : can(regex("^[A-Z][A-Z0-9_]*$", e.name))])
    error_message = "bridge_extra_environment names must be UPPER_SNAKE_CASE environment variable names."
  }

  validation {
    condition     = length(distinct([for e in var.bridge_extra_environment : e.name])) == length(var.bridge_extra_environment)
    error_message = "bridge_extra_environment names must be unique."
  }

  validation {
    condition = alltrue([
      for e in var.bridge_extra_environment : !contains([
        "RUN_MODE", "SERVICE_ADDRESS", "DATABASE_URL", "REDIS_URL", "JWT_SECRET",
        "STELLAR_NETWORK", "STELLAR_HORIZON_URL", "STELLAR_RPC_URL", "STELLAR_NETWORK_PASSPHRASE",
        "SOROBAN_CONTRACT_ID", "DEBUG_MODE", "SNS_TOPIC_ARN", "SQS_QUEUE_URL", "AWS_REGION",
        "SES_FROM_ADDRESS", "FCM_PROJECT_ID", "SEED_PROTECTION_BACKEND", "KMS_SEED_KEY_ID",
        "VAULT_ADDR", "VAULT_TRANSIT_KEY", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_SERVICE_NAME",
        "CORS_ALLOWED_ORIGINS", "PUBLIC_ENDPOINT",
      ], e.name)
    ])
    error_message = "bridge_extra_environment must not set a variable Terraform already manages (RUN_MODE, SERVICE_ADDRESS, DATABASE_URL, REDIS_URL, JWT_SECRET, STELLAR_*, SOROBAN_CONTRACT_ID, DEBUG_MODE, SNS_TOPIC_ARN, SQS_QUEUE_URL, AWS_REGION, SES_FROM_ADDRESS, FCM_PROJECT_ID, SEED_PROTECTION_BACKEND, KMS_SEED_KEY_ID, VAULT_ADDR, VAULT_TRANSIT_KEY, OTEL_*, CORS_ALLOWED_ORIGINS, PUBLIC_ENDPOINT): use the dedicated variable instead."
  }

  validation {
    condition = alltrue([
      for e in var.bridge_extra_environment :
      !can(regex("(_SECRET|_SECRET_PREVIOUS|_TOKEN|_PASSWORD|_SEED|_PRIVATE_KEY|_API_KEY|_SECRET_KEY|_ACCESS_KEY|_SERVICE_ACCOUNT_KEY)$", e.name))
    ])
    error_message = "bridge_extra_environment is for NON-SECRET values only (they are plaintext in the task definition, plan and state): names ending in _SECRET, _TOKEN, _PASSWORD, _SEED, _PRIVATE_KEY, _API_KEY, _SECRET_KEY, _ACCESS_KEY or _SERVICE_ACCOUNT_KEY are refused — inject credentials through Secrets Manager and the task definition secrets block instead."
  }
}
