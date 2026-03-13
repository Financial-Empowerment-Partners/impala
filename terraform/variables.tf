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
  description = "Deployment environment (staging, production)"
  type        = string
  default     = "staging"
}

# --- Networking ---

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones to use"
  type        = number
  default     = 2
}

# --- ECS ---

variable "server_desired_count" {
  description = "Desired number of server task instances"
  type        = number
  default     = 2
}

variable "worker_desired_count" {
  description = "Desired number of worker task instances"
  type        = number
  default     = 1
}

variable "server_cpu" {
  description = "CPU units for server task (256 = 0.25 vCPU)"
  type        = number
  default     = 256
}

variable "server_memory" {
  description = "Memory in MiB for server task"
  type        = number
  default     = 512
}

variable "worker_cpu" {
  description = "CPU units for worker task"
  type        = number
  default     = 256
}

variable "worker_memory" {
  description = "Memory in MiB for worker task"
  type        = number
  default     = 512
}

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

# --- RDS ---

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

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
  default     = true
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

# --- SQS ---

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

# --- Secrets ---

variable "jwt_secret" {
  description = "JWT signing secret for impala-bridge"
  type        = string
  sensitive   = true
}

# --- Optional HTTPS ---

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS listener (optional)"
  type        = string
  default     = ""
}

# --- Auto Scaling ---

variable "server_min_count" {
  description = "Minimum number of server tasks for autoscaling"
  type        = number
  default     = 2
}

variable "server_max_count" {
  description = "Maximum number of server tasks for autoscaling"
  type        = number
  default     = 10
}

variable "worker_min_count" {
  description = "Minimum number of worker tasks for autoscaling"
  type        = number
  default     = 1
}

variable "worker_max_count" {
  description = "Maximum number of worker tasks for autoscaling"
  type        = number
  default     = 5
}

variable "autoscaling_cpu_threshold" {
  description = "CPU utilization percentage to trigger scale out"
  type        = number
  default     = 85
}

variable "autoscaling_memory_threshold" {
  description = "Memory utilization percentage to trigger scale out"
  type        = number
  default     = 90
}

variable "autoscaling_latency_threshold_ms" {
  description = "ALB target response time in milliseconds to trigger scale out"
  type        = number
  default     = 250
}

variable "autoscaling_scale_in_cooldown" {
  description = "Cooldown in seconds before allowing scale in"
  type        = number
  default     = 300
}

variable "autoscaling_scale_out_cooldown" {
  description = "Cooldown in seconds before allowing scale out"
  type        = number
  default     = 60
}

# --- Monitoring ---

variable "alert_email" {
  description = "Email address for CloudWatch alarm notifications (optional)"
  type        = string
  default     = ""
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

# --- Observability (SigNoz) ---

variable "signoz_endpoint" {
  description = "SigNoz OTLP endpoint (e.g. https://ingest.us.signoz.cloud:443). Enables OTEL Collector sidecar when set."
  type        = string
  default     = ""
}

variable "signoz_access_token" {
  description = "SigNoz ingestion access token (required when signoz_endpoint is set)"
  type        = string
  default     = ""
  sensitive   = true
}

# --- Disaster Recovery ---

variable "dr_enabled" {
  description = "Enable cross-region disaster recovery infrastructure"
  type        = bool
  default     = false
}

variable "dr_region" {
  description = "AWS region for disaster recovery resources"
  type        = string
  default     = "us-west-2"
}

variable "dr_vpc_cidr" {
  description = "CIDR block for the DR VPC"
  type        = string
  default     = "10.1.0.0/16"
}

variable "dr_server_desired_count" {
  description = "Desired number of server tasks in DR region"
  type        = number
  default     = 1
}

variable "dr_worker_desired_count" {
  description = "Desired number of worker tasks in DR region"
  type        = number
  default     = 1
}

variable "domain_name" {
  description = "Domain name for Route 53 failover DNS (e.g. example.com). Creates api.example.com records."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID for failover DNS records"
  type        = string
  default     = ""
}

variable "rds_backup_retention_days" {
  description = "Number of days to retain automated RDS backups (1-35)"
  type        = number
  default     = 7
}

# --- Stellar ---

variable "stellar_horizon_url" {
  description = "Stellar Horizon API URL"
  type        = string
  default     = "https://horizon.stellar.org"
}

variable "stellar_rpc_url" {
  description = "Stellar Soroban RPC URL"
  type        = string
  default     = "https://soroban-testnet.stellar.org"
}
