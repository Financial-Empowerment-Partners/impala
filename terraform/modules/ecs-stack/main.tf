# =============================================================================
# ecs-stack module — one full bridge environment (network + RDS + Redis +
# SNS/SQS + Secrets Manager + ALB + ECS), shared by the testnet and live
# stacks. Extracted verbatim from the pre-module testnet.tf / live.tf.
#
# Inner resources keep `count = 1` (the enable toggle moved to the `count` on
# the module call) so every instance keeps its legacy `[0]` state index —
# required for the zero-diff `moved {}` migration. See ../../README.md.
# Since the C3 hardening pass some counts are variables (az_count/nat_count/
# alarm + access-log toggles) whose DEFAULTS reproduce the legacy single
# instance, so a bare module call still plans 0/0/0 post-migration.
# =============================================================================

locals {
  # One NAT gateway per AZ unless the caller deliberately runs fewer
  # (e.g. testnet: az_count = 2, nat_count = 1).
  nat_count = coalesce(var.nat_count, var.az_count)
}

# --- Availability Zones ---

data "aws_availability_zones" "this" {
  count = 1
  state = "available"
}

# =============================================================================
# VPC + Networking (az_count AZs; defaults to the historical single AZ)
#
# PRE-EXISTING PROBLEM, surfaced as a knob rather than silently fixed: with
# the default az_count = 1 this stack creates ONE public and ONE private
# subnet, but a real apply rejects that topology — aws_db_subnet_group
# requires subnets in at least 2 AZs and aws_lb requires at least 2 public
# subnets. If applies have been failing on those resources, set az_count = 2
# (and nat_count = 1 to stay on a single NAT gateway) on the module call.
# =============================================================================

resource "aws_vpc" "this" {
  count = 1

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.name_prefix}-vpc-${var.env}"
  }
}

resource "aws_subnet" "public" {
  count = var.az_count

  vpc_id            = aws_vpc.this[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.this[0].names[count.index]

  # Public subnets host only the ALB and NAT gateway and need public IPs;
  # ECS tasks, RDS and Redis live in the private subnets below.
  #trivy:ignore:AVD-AWS-0164
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-${var.env}-public-${count.index}"
  }
}

resource "aws_subnet" "private" {
  count = var.az_count

  vpc_id            = aws_vpc.this[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.this[0].names[count.index]

  tags = {
    Name = "${var.name_prefix}-${var.env}-private-${count.index}"
  }
}

resource "aws_internet_gateway" "this" {
  count = 1

  vpc_id = aws_vpc.this[0].id

  tags = {
    Name = "${var.name_prefix}-igw-${var.env}"
  }
}

resource "aws_eip" "nat" {
  count = local.nat_count

  domain = "vpc"

  tags = {
    Name = "${var.name_prefix}-${var.env}-nat-eip-${count.index}"
  }
}

resource "aws_nat_gateway" "this" {
  count = local.nat_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.name_prefix}-${var.env}-nat-${count.index}"
  }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  count = 1

  vpc_id = aws_vpc.this[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }

  tags = {
    Name = "${var.name_prefix}-${var.env}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count = var.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count = var.az_count

  vpc_id = aws_vpc.this[0].id

  route {
    cidr_block = "0.0.0.0/0"
    # With nat_count < az_count the extra AZs share the last NAT gateway.
    nat_gateway_id = aws_nat_gateway.this[min(count.index, local.nat_count - 1)].id
  }

  tags = {
    Name = "${var.name_prefix}-${var.env}-private-rt-${count.index}"
  }
}

resource "aws_route_table_association" "private" {
  count = var.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# =============================================================================
# Security Groups
# =============================================================================

resource "aws_security_group" "alb" {
  count = 1

  name_prefix = "${var.name_prefix}-${var.env}-alb-"
  description = "Allow HTTP/HTTPS inbound to ${var.env} ALB"
  vpc_id      = aws_vpc.this[0].id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Open egress is by design: tasks pull from ECR/AWS APIs and the bridge
  # calls Stellar Horizon/Soroban RPC plus operator webhook endpoints.
  #trivy:ignore:AVD-AWS-0104
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-${var.env}-alb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "ecs_tasks" {
  count = 1

  name_prefix = "${var.name_prefix}-${var.env}-ecs-"
  description = "Allow inbound from ${var.env} ALB, outbound all"
  vpc_id      = aws_vpc.this[0].id

  ingress {
    description     = "From ${var.env} ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb[0].id]
  }

  # Open egress is by design: tasks pull from ECR/AWS APIs and the bridge
  # calls Stellar Horizon/Soroban RPC plus operator webhook endpoints.
  #trivy:ignore:AVD-AWS-0104
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-${var.env}-ecs-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "rds" {
  count = 1

  name_prefix = "${var.name_prefix}-${var.env}-rds-"
  description = "Allow PostgreSQL from ${var.env} ECS tasks"
  vpc_id      = aws_vpc.this[0].id

  ingress {
    description     = "PostgreSQL from ${var.env} ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks[0].id]
  }

  tags = {
    Name = "${var.name_prefix}-${var.env}-rds-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "redis" {
  count = 1

  name_prefix = "${var.name_prefix}-${var.env}-redis-"
  description = "Allow Redis from ${var.env} ECS tasks"
  vpc_id      = aws_vpc.this[0].id

  ingress {
    description     = "Redis from ${var.env} ECS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks[0].id]
  }

  tags = {
    Name = "${var.name_prefix}-${var.env}-redis-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# ALB
# =============================================================================

# Internet-facing ALB is the public API entry point for this stack — by design.
#trivy:ignore:AVD-AWS-0053
resource "aws_lb" "this" {
  count = 1

  name               = "${var.name_prefix}-alb-${var.env}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = aws_subnet.public[*].id

  # Drop requests with malformed/invalid HTTP headers before they reach the
  # bridge (header-smuggling hardening; AVD-AWS-0052). No functional impact.
  drop_invalid_header_fields = true

  dynamic "access_logs" {
    for_each = var.alb_access_logs_enabled ? [1] : []
    content {
      bucket  = aws_s3_bucket.alb_logs[0].id
      enabled = true
    }
  }

  tags = {
    Name = "${var.name_prefix}-alb-${var.env}"
  }

  # ELB refuses to enable access logging until the bucket policy grants the
  # ELB service account PutObject — make the ordering explicit.
  depends_on = [aws_s3_bucket_policy.alb_logs]
}

resource "aws_lb_target_group" "server" {
  count = 1

  name        = "${var.name_prefix}-tg-${var.env}"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this[0].id
  target_type = "ip"

  # Readiness, not liveness. /readyz answers 200 only when Postgres AND Redis
  # both answer (impala-bridge/src/handlers/health.rs, empty body); /health
  # answers 200 with a JSON body even while degraded (impalactl + openapi
  # depend on that shape) and must never be a probe target. 8 x 30 s = 4 min
  # of sustained dependency failure before a target is pulled — longer than
  # a Multi-AZ RDS / ElastiCache failover, so a failover does not cascade
  # into ECS replacing every task. Full rationale on
  # aws_lb_target_group.server in ../../alb.tf.
  health_check {
    path                = "/readyz"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 8
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = {
    Name = "${var.name_prefix}-tg-${var.env}"
  }
}

# Plain-HTTP forward exists only for certificate-less (testnet/dev) stacks;
# the 301 redirect to HTTPS activates as soon as certificate_arn is set.
#trivy:ignore:AVD-AWS-0054
resource "aws_lb_listener" "http" {
  count = 1

  load_balancer_arn = aws_lb.this[0].arn
  port              = 80
  protocol          = "HTTP"

  # As soon as an ACM certificate is attached (certificate_arn != "", which
  # also creates the HTTPS listener below), plain HTTP 301-redirects to HTTPS
  # — mirrors the modules/impala-stack http_redirect listener. Without a
  # certificate the legacy forward action is preserved.
  default_action {
    type             = var.certificate_arn != "" ? "redirect" : "forward"
    target_group_arn = var.certificate_arn != "" ? null : aws_lb_target_group.server[0].arn

    dynamic "redirect" {
      for_each = var.certificate_arn != "" ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  count = var.certificate_arn != "" ? 1 : 0

  load_balancer_arn = aws_lb.this[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server[0].arn
  }
}

# =============================================================================
# ElastiCache (defaults: single node, no failover, no TLS/AUTH — the C3 knobs
# redis_num_cache_clusters / transit_encryption_mode / redis_auth_enabled
# upgrade this per stack)
# =============================================================================

# ElastiCache AUTH token constraints: 16-128 printable ASCII characters,
# excluding '/', '"', '@' and spaces. The token is also embedded verbatim in
# the rediss:// URL secret below, so keep it alphanumeric (special = false) —
# that satisfies the ElastiCache charset AND avoids URL-encoding pitfalls.
resource "random_password" "redis_auth_token" {
  count = var.redis_auth_enabled ? 1 : 0

  length  = 32
  special = false
}

resource "aws_elasticache_subnet_group" "this" {
  count = 1

  name       = "${var.name_prefix}-redis-subnet-${var.env}"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${var.name_prefix}-redis-subnet-${var.env}"
  }
}

# Opt-in stack parameter group (var.redis_parameter_group_enabled):
#
#   - maxmemory-policy = noeviction: the bridge's Redis-backed security checks
#     (rate limiting, account lockout, MFA brute-force tracking, JWT
#     revocation — impala-bridge/src/redis_helpers.rs) are FAIL-CLOSED: when
#     Redis errors, the request is rejected. default.redis7 is volatile-lru,
#     under which a FULL Redis silently evicts exactly those rate-limit/
#     lockout/revocation keys — turning memory pressure into a security-check
#     BYPASS. With noeviction a full Redis returns write errors instead, which
#     the fail-closed helpers surface as denials. Full-Redis must error, not
#     evict — eviction = security bypass.
#   - timeout = 0: never disconnect idle clients — deadpool-redis pools
#     long-lived connections (0 is also the redis7 default, pinned explicitly).
#
# Both parameters apply in-place; no node replacement or reboot.
resource "aws_elasticache_parameter_group" "this" {
  count = var.redis_parameter_group_enabled ? 1 : 0

  name        = "${var.name_prefix}-redis7-${var.env}"
  family      = "redis7"
  description = "${title(var.env)} Redis parameters for ${var.name_prefix} (noeviction: fail-closed security keys)"

  parameter {
    name  = "maxmemory-policy"
    value = "noeviction"
  }

  parameter {
    name  = "timeout"
    value = "0"
  }

  tags = {
    Name = "${var.name_prefix}-redis7-${var.env}"
  }
}

resource "aws_elasticache_replication_group" "this" {
  count = 1

  replication_group_id = "${var.name_prefix}-redis-${var.env}"
  description          = "${title(var.env)} Redis replication group for ${var.name_prefix}"

  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.redis_node_type
  num_cache_clusters   = var.redis_num_cache_clusters
  port                 = 6379
  parameter_group_name = var.redis_parameter_group_enabled ? aws_elasticache_parameter_group.this[0].name : "default.redis7"

  subnet_group_name  = aws_elasticache_subnet_group.this[0].name
  security_group_ids = [aws_security_group.redis[0].id]

  # Failover + Multi-AZ are only valid with >= 2 cache clusters, so both are
  # derived from the node count rather than set independently.
  automatic_failover_enabled = var.redis_num_cache_clusters > 1
  multi_az_enabled           = var.redis_num_cache_clusters > 1

  at_rest_encryption_enabled = true
  # Staged TLS rollout ("" -> "preferred" -> "required"): "preferred" enables
  # TLS while still accepting the bridge's current plaintext redis://
  # connections; the per-stack flip to "required" is gated on the bridge
  # rediss:// deploy (workstream A5). See var.transit_encryption_mode.
  transit_encryption_enabled = var.transit_encryption_mode != ""
  transit_encryption_mode    = var.transit_encryption_mode != "" ? var.transit_encryption_mode : null

  # Rollout note: if AWS rejects enabling TLS and AUTH in one modify call,
  # apply transit_encryption_mode = "preferred" first, then redis_auth_enabled.
  auth_token = var.redis_auth_enabled ? random_password.redis_auth_token[0].result : null
  # Explicit because AWS provider v6 removed the implicit "ROTATE" default
  # (v6 upgrade guide); "ROTATE" reproduces the v5 behavior.
  auth_token_update_strategy = var.redis_auth_enabled ? "ROTATE" : null

  tags = {
    Name = "${var.name_prefix}-redis-${var.env}"
  }
}

# =============================================================================
# RDS (defaults: single-AZ, 1-day backups, unprotected — the C3 knobs
# rds_multi_az / rds_backup_retention_period / rds_deletion_protection /
# rds_skip_final_snapshot upgrade this per stack)
# =============================================================================

resource "random_password" "rds_password" {
  count = 1

  length  = 32
  special = false
}

resource "aws_kms_key" "rds" {
  count = 1

  description             = "KMS key for ${var.env} RDS encryption - ${var.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${var.name_prefix}-rds-kms-${var.env}"
  }
}

resource "aws_db_subnet_group" "this" {
  count = 1

  name       = "${var.name_prefix}-db-subnet-${var.env}"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${var.name_prefix}-db-subnet-${var.env}"
  }
}

# TLS-only PostgreSQL (var.rds_force_ssl_enabled). rds.force_ssl is a STATIC
# parameter, hence apply_method = "pending-reboot" — and with
# apply_immediately = true on the instance, the parameter-group swap itself
# reboots the DB. Roll out testnet before live; see the rollout sequence on
# var.rds_force_ssl_enabled in variables.tf.
resource "aws_db_parameter_group" "this" {
  count = var.rds_force_ssl_enabled ? 1 : 0

  name = "${var.name_prefix}-pg16-${var.env}"
  # postgres16 for the default rds_engine_version = "16.4".
  family = "postgres${split(".", var.rds_engine_version)[0]}"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  tags = {
    Name = "${var.name_prefix}-pg16-${var.env}"
  }
}

resource "aws_db_instance" "this" {
  count = 1

  identifier     = "${var.name_prefix}-db-${var.env}"
  engine         = "postgres"
  engine_version = var.rds_engine_version
  instance_class = var.rds_instance_class

  allocated_storage = 20
  # 0 = storage autoscaling off (legacy); > 0 lets RDS grow the allocation
  # online up to the cap (both stacks set 100).
  max_allocated_storage = var.rds_max_allocated_storage
  # gp3 default: the first apply after the WS4 change migrates legacy gp2
  # storage IN-PLACE — online, but the instance passes through
  # "storage-optimization" and storage cannot be modified again for ~6 h.
  storage_type      = var.rds_storage_type
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds[0].arn

  db_name  = "impala"
  username = "impala_admin"
  password = random_password.rds_password[0].result

  db_subnet_group_name   = aws_db_subnet_group.this[0].name
  vpc_security_group_ids = [aws_security_group.rds[0].id]
  # null = the engine-default parameter group (legacy behavior).
  parameter_group_name = var.rds_force_ssl_enabled ? aws_db_parameter_group.this[0].name : null

  multi_az            = var.rds_multi_az
  publicly_accessible = false

  skip_final_snapshot       = var.rds_skip_final_snapshot
  final_snapshot_identifier = var.rds_skip_final_snapshot ? null : "${var.name_prefix}-db-${var.env}-final"
  deletion_protection       = var.rds_deletion_protection

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds[0].arn

  backup_retention_period = var.rds_backup_retention_period
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  apply_immediately = true

  tags = {
    Name = "${var.name_prefix}-db-${var.env}"
  }
}

# =============================================================================
# SNS/SQS (Worker Queue)
# =============================================================================

# AWS-managed alias/aws/sns key per the C3 hardening spec; a CMK adds cost
# and rotation burden with no threat-model benefit for internal job fan-out.
#trivy:ignore:AVD-AWS-0136
resource "aws_sns_topic" "jobs" {
  count = 1

  name = "${var.name_prefix}-jobs-${var.env}"

  # "alias/aws/sns" per stack; "" (default) keeps the legacy unencrypted
  # topic. The AWS-managed SNS key works for the SQS subscription because SNS
  # itself decrypts before delivery — the constraint is on the QUEUE key, see
  # the sqs_managed_sse_enabled note below.
  kms_master_key_id = var.sns_kms_master_key_id != "" ? var.sns_kms_master_key_id : null

  tags = {
    Name = "${var.name_prefix}-jobs-${var.env}"
  }
}

resource "aws_sqs_queue" "worker_dlq" {
  count = 1

  name                      = "${var.name_prefix}-worker-dlq-${var.env}"
  message_retention_seconds = 1209600

  # SSE-SQS (SQS-owned keys), NOT kms_master_key_id = "alias/aws/sqs": SNS
  # cannot deliver to a queue encrypted with the AWS-managed SQS key — that
  # key's policy only allows use via SQS by account principals, so SNS gets
  # no kms:GenerateDataKey and every published job would be silently dropped.
  # null (default) leaves the attribute unmanaged (legacy behavior).
  sqs_managed_sse_enabled = var.sqs_managed_sse_enabled

  tags = {
    Name = "${var.name_prefix}-worker-dlq-${var.env}"
  }
}

resource "aws_sqs_queue" "worker" {
  count = 1

  name                       = "${var.name_prefix}-worker-${var.env}"
  visibility_timeout_seconds = var.sqs_visibility_timeout_seconds
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20

  # Same SSE-SQS-not-alias/aws/sqs rationale as the DLQ above.
  sqs_managed_sse_enabled = var.sqs_managed_sse_enabled

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.worker_dlq[0].arn
    maxReceiveCount     = var.sqs_max_receive_count
  })

  tags = {
    Name = "${var.name_prefix}-worker-${var.env}"
  }
}

resource "aws_sns_topic_subscription" "worker" {
  count = 1

  topic_arn = aws_sns_topic.jobs[0].arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.worker[0].arn
}

resource "aws_sqs_queue_policy" "worker" {
  count = 1

  queue_url = aws_sqs_queue.worker[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSNSSend"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.worker[0].arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.jobs[0].arn
          }
        }
      }
    ]
  })
}

# =============================================================================
# Secrets Manager
# =============================================================================

resource "aws_secretsmanager_secret" "database_url" {
  count = 1

  name        = "${var.name_prefix}-database-url-${var.env}"
  description = "DATABASE_URL for ${var.env} impala-bridge"
}

resource "aws_secretsmanager_secret_version" "database_url" {
  count = 1

  secret_id = aws_secretsmanager_secret.database_url[0].id
  # ?sslmode=require ONLY under rds_force_ssl_enabled (otherwise byte-identical
  # to the legacy URL). Bridge-compatible without code changes: sqlx is built
  # with tls-rustls-aws-lc-rs and sslmode=require performs TLS without CA
  # verification, so no RDS CA bundle is needed. Tasks only pick the new value
  # up on the next ECS deployment — see var.rds_force_ssl_enabled.
  secret_string = "postgresql://impala_admin:${random_password.rds_password[0].result}@${aws_db_instance.this[0].endpoint}/impala${var.rds_force_ssl_enabled ? "?sslmode=require" : ""}"
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  count = 1

  name        = "${var.name_prefix}-jwt-secret-${var.env}"
  description = "JWT signing secret for ${var.env} impala-bridge"
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  count = 1

  secret_id     = aws_secretsmanager_secret.jwt_secret[0].id
  secret_string = var.jwt_secret
}

# With redis_auth_enabled the connection string embeds the AUTH token, so
# REDIS_URL moves from a plain container environment variable to a secret
# (same pattern as database_url / jwt_secret above).
resource "aws_secretsmanager_secret" "redis_url" {
  count = var.redis_auth_enabled ? 1 : 0

  name        = "${var.name_prefix}-redis-url-${var.env}"
  description = "REDIS_URL (TLS + AUTH token) for ${var.env} impala-bridge"
}

resource "aws_secretsmanager_secret_version" "redis_url" {
  count = var.redis_auth_enabled ? 1 : 0

  secret_id     = aws_secretsmanager_secret.redis_url[0].id
  secret_string = "rediss://:${random_password.redis_auth_token[0].result}@${aws_elasticache_replication_group.this[0].primary_endpoint_address}:6379"
}

# =============================================================================
# IAM Roles
# =============================================================================

resource "aws_iam_role" "ecs_task_execution" {
  count = 1

  name = "${var.name_prefix}-ecs-exec-${var.env}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  count = 1

  role       = aws_iam_role.ecs_task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  count = 1

  name = "${var.name_prefix}-exec-secrets-${var.env}"
  role = aws_iam_role.ecs_task_execution[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = concat(
          [
            aws_secretsmanager_secret.database_url[0].arn,
            aws_secretsmanager_secret.jwt_secret[0].arn,
          ],
          var.redis_auth_enabled ? [aws_secretsmanager_secret.redis_url[0].arn] : [],
        )
      }
    ]
  })
}

resource "aws_iam_role" "ecs_task" {
  count = 1

  name = "${var.name_prefix}-ecs-task-${var.env}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_permissions" {
  count = 1

  name = "${var.name_prefix}-task-permissions-${var.env}"
  role = aws_iam_role.ecs_task[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Effect = "Allow"
          Action = [
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueAttributes",
            "sqs:GetQueueUrl",
          ]
          Resource = aws_sqs_queue.worker[0].arn
        },
        {
          Effect   = "Allow"
          Action   = "sns:Publish"
          Resource = aws_sns_topic.jobs[0].arn
        },
        {
          Effect = "Allow"
          Action = [
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          # Scoped to the two stack log groups; ":*" covers their log streams.
          Resource = [
            "${aws_cloudwatch_log_group.server[0].arn}:*",
            "${aws_cloudwatch_log_group.worker[0].arn}:*",
          ]
        },
      ],
      # SES statement only exists when a sender address is configured, and is
      # scoped to the verified identity when its ARN is supplied ("" keeps the
      # legacy Resource = "*").
      var.ses_from_address != "" ? [
        {
          Effect = "Allow"
          Action = [
            "ses:SendEmail",
            "ses:SendRawEmail",
          ]
          Resource = var.ses_identity_arn != "" ? var.ses_identity_arn : "*"
        }
      ] : [],
    )
  })
}

# =============================================================================
# CloudWatch Log Groups
# =============================================================================

resource "aws_cloudwatch_log_group" "server" {
  count = 1

  name              = "/ecs/${var.name_prefix}-server-${var.env}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "worker" {
  count = 1

  name              = "/ecs/${var.name_prefix}-worker-${var.env}"
  retention_in_days = 30
}

# =============================================================================
# ECS Cluster + Services
# =============================================================================

resource "aws_ecs_cluster" "this" {
  count = 1

  name = "${var.name_prefix}-cluster-${var.env}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${var.name_prefix}-cluster-${var.env}"
  }
}

# Server Task Definition
resource "aws_ecs_task_definition" "server" {
  count = 1

  family                   = "${var.name_prefix}-server-${var.env}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.server_cpu
  memory                   = var.server_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.ecs_task[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode([
    {
      name      = "impala-bridge-server"
      image     = var.container_image
      essential = true

      readonlyRootFilesystem = true
      user                   = "1000:1000"

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      # Element order must stay byte-identical to the pre-module env list or
      # container_definitions churns. Slot 7 holds the per-network optionals:
      # testnet passes SOROBAN_CONTRACT_ID (present even when empty), live
      # passes STELLAR_NETWORK_PASSPHRASE — hence the null (not "") checks.
      # With redis_auth_enabled the REDIS_URL slot is dropped here and the
      # variable is served from Secrets Manager via the secrets list instead
      # (the rediss:// URL embeds the AUTH token).
      environment = concat(
        [
          { name = "RUN_MODE", value = "server" },
          { name = "SERVICE_ADDRESS", value = "0.0.0.0:8080" },
        ],
        var.redis_auth_enabled ? [] : [{ name = "REDIS_URL", value = "redis://${aws_elasticache_replication_group.this[0].primary_endpoint_address}:6379" }],
        [
          { name = "STELLAR_NETWORK", value = var.stellar.network },
          { name = "STELLAR_HORIZON_URL", value = var.stellar.horizon_url },
          { name = "STELLAR_RPC_URL", value = var.stellar.rpc_url },
        ],
        var.stellar.soroban_contract_id != null ? [{ name = "SOROBAN_CONTRACT_ID", value = var.stellar.soroban_contract_id }] : [],
        var.stellar.network_passphrase != null ? [{ name = "STELLAR_NETWORK_PASSPHRASE", value = var.stellar.network_passphrase }] : [],
        [
          { name = "DEBUG_MODE", value = var.stellar.debug_mode },
          { name = "SNS_TOPIC_ARN", value = aws_sns_topic.jobs[0].arn },
          { name = "AWS_REGION", value = var.aws_region },
          { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
          { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
        ],
        # Appended after the historical list so the element order above stays
        # intact ([] default = zero churn).
        var.seed_protection_environment,
        # CORS_ALLOWED_ORIGINS / PUBLIC_ENDPOINT only when the caller sets
        # them (null default = omitted, so the testnet task definition stays
        # byte-identical). The bridge exits on wildcard CORS with
        # STELLAR_NETWORK=pubnet, which is why variables.tf requires
        # cors_allowed_origins for pubnet stacks.
        var.cors_allowed_origins != null ? [{ name = "CORS_ALLOWED_ORIGINS", value = var.cors_allowed_origins }] : [],
        var.public_endpoint != null ? [{ name = "PUBLIC_ENDPOINT", value = var.public_endpoint }] : [],
        # Operator-supplied non-secret extras, always last ([] default).
        var.extra_environment,
      )

      secrets = concat(
        [
          {
            name      = "DATABASE_URL"
            valueFrom = aws_secretsmanager_secret.database_url[0].arn
          },
          {
            name      = "JWT_SECRET"
            valueFrom = aws_secretsmanager_secret.jwt_secret[0].arn
          },
        ],
        var.redis_auth_enabled ? [
          {
            name      = "REDIS_URL"
            valueFrom = aws_secretsmanager_secret.redis_url[0].arn
          }
        ] : [],
      )

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.server[0].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "server"
        }
      }
    }
  ])
}

# Worker Task Definition
resource "aws_ecs_task_definition" "worker" {
  count = 1

  family                   = "${var.name_prefix}-worker-${var.env}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.ecs_task[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode([
    {
      name      = "impala-bridge-worker"
      image     = var.container_image
      essential = true

      readonlyRootFilesystem = true
      user                   = "1000:1000"

      # Same slot-7 optionals + REDIS_URL env->secret rules as the server
      # task definition above.
      environment = concat(
        [
          { name = "RUN_MODE", value = "worker" },
          { name = "SQS_QUEUE_URL", value = aws_sqs_queue.worker[0].url },
        ],
        var.redis_auth_enabled ? [] : [{ name = "REDIS_URL", value = "redis://${aws_elasticache_replication_group.this[0].primary_endpoint_address}:6379" }],
        [
          { name = "STELLAR_NETWORK", value = var.stellar.network },
          { name = "STELLAR_HORIZON_URL", value = var.stellar.horizon_url },
          { name = "STELLAR_RPC_URL", value = var.stellar.rpc_url },
        ],
        var.stellar.soroban_contract_id != null ? [{ name = "SOROBAN_CONTRACT_ID", value = var.stellar.soroban_contract_id }] : [],
        var.stellar.network_passphrase != null ? [{ name = "STELLAR_NETWORK_PASSPHRASE", value = var.stellar.network_passphrase }] : [],
        [
          { name = "DEBUG_MODE", value = var.stellar.debug_mode },
          { name = "AWS_REGION", value = var.aws_region },
          { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
          { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
        ],
        # Appended after the historical list so the element order above stays
        # intact ([] default = zero churn). CORS/PUBLIC_ENDPOINT are
        # server-only; the operator extras are always last.
        var.seed_protection_environment,
        var.extra_environment,
      )

      secrets = concat(
        [
          {
            name      = "DATABASE_URL"
            valueFrom = aws_secretsmanager_secret.database_url[0].arn
          },
          {
            name      = "JWT_SECRET"
            valueFrom = aws_secretsmanager_secret.jwt_secret[0].arn
          },
        ],
        var.redis_auth_enabled ? [
          {
            name      = "REDIS_URL"
            valueFrom = aws_secretsmanager_secret.redis_url[0].arn
          }
        ] : [],
      )

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.worker[0].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "worker"
        }
      }
    }
  ])
}

# Server ECS Service
resource "aws_ecs_service" "server" {
  count = 1

  name            = "${var.name_prefix}-server-${var.env}"
  cluster         = aws_ecs_cluster.this[0].id
  task_definition = aws_ecs_task_definition.server[0].arn
  desired_count   = var.server_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks[0].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.server[0].arn
    container_name   = "impala-bridge-server"
    container_port   = 8080
  }

  # A fresh task gets 120 s to open its DB/Redis pools before ECS acts on
  # ALB health (the /readyz check above is a real dependency check). Only
  # valid on services with a load_balancer block — never on the worker.
  health_check_grace_period_seconds = 120

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener.http]
}

# Worker ECS Service
resource "aws_ecs_service" "worker" {
  count = 1

  name            = "${var.name_prefix}-worker-${var.env}"
  cluster         = aws_ecs_cluster.this[0].id
  task_definition = aws_ecs_task_definition.worker[0].arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks[0].id]
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [desired_count]
  }
}
