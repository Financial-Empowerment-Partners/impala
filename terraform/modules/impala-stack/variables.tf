# Inputs for the impala cluster. The root module keeps its original
# var.impala_* surface and maps it onto these.

variable "vpc_cidr" {
  description = "CIDR block for the impala VPC"
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the impala ALBs (HTTPS-only listener)"
  type        = string
}

variable "ecr_repository_urls" {
  description = "Map of service name (impala-api / impala-admin) to ECR repository URL"
  type        = map(string)
}

variable "container_image_tag" {
  description = "Docker image tag to deploy"
  type        = string
}

variable "container_architecture" {
  description = "CPU architecture for ECS tasks: X86_64 or ARM64 (Graviton)"
  type        = string
}

variable "aws_region" {
  description = "AWS region (KMS key policy + awslogs option)"
  type        = string
}

variable "account_id" {
  description = "AWS account id (root data.aws_caller_identity.current), used in the KMS key policy"
  type        = string
}

# =============================================================================
# WS4 hardening knobs (terraform stream). Defaults preserve pre-WS4 behavior
# EXCEPT waf_enabled (deliberately default-ON — see waf.tf).
# =============================================================================

variable "waf_enabled" {
  description = <<-EOT
    Attach one shared WAFv2 web ACL (AWS managed Common/KnownBadInputs/SQLi
    rule groups + a per-IP rate-based block rule) to both service ALBs.
    Deliberately default-ON (breaks the zero-diff module convention per the
    WS4 spec); set false to opt out. See waf.tf.
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

variable "alarm_sns_topic_arn" {
  description = <<-EOT
    SNS topic ARN to receive alarm_actions + ok_actions from both service
    CloudWatch alarms (the root passes the ops.tf topic when
    var.ops_alerts_enabled). "" keeps the legacy console-only alarms.
  EOT
  type        = string
  default     = ""
}

variable "private_tasks_enabled" {
  description = <<-EOT
    Move the ECS tasks off public IPs into private subnets behind a single
    NAT gateway (see the blast-radius/cost comment in main.tf). Default-off:
    the NAT gateway is ~USD 33/mo + data processing — an operator cost
    decision, flipped in ../../impala.tf after sign-off. The switch is an
    in-place service update (new deployment, no service replacement).
  EOT
  type        = bool
  default     = false
}
