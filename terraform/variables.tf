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
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
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
  description = "ACM certificate ARN for live HTTPS listener (recommended for production)"
  type        = string
  default     = ""
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
  description = "ACM certificate ARN for the primary ALB HTTPS listener (empty = HTTP only)"
  type        = string
  default     = ""
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

# --- Stellar endpoints (primary bridge) ---

variable "stellar_horizon_url" {
  description = "Stellar Horizon API URL for the primary bridge"
  type        = string
  default     = "https://horizon-testnet.stellar.org"
}

variable "stellar_rpc_url" {
  description = "Stellar Soroban RPC URL for the primary bridge"
  type        = string
  default     = "https://soroban-testnet.stellar.org"
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
