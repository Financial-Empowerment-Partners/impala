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

# --- ECR cross-region replication ---

variable "dr_enabled" {
  description = "Enable cross-region ECR replication (image-only DR; no compute mirroring)"
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
