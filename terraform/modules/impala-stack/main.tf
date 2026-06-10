# =============================================================================
# impala-stack module — minimal Fargate stack for impala-api and impala-admin.
# Public-subnet networking by default (tasks opt into private subnets + a
# single NAT via var.private_tasks_enabled); two separate public ALBs (one per
# service); single task per service; image URLs come from the root ECR repos
# (ecr.tf aws_ecr_repository.deploy["impala-api"|"impala-admin"]) via
# var.ecr_repository_urls.
#
# Extracted verbatim from the pre-module impala.tf. The enable toggle moved to
# `count` on the module call; former count-gated singletons dropped their
# inner count (state index `[0]` -> none, handled by moved-impala.tf), while
# per-service for_each keys and the two-subnet `count = 2` are preserved
# exactly. See ../../README.md.
#
# Security hardening (OWASP Top-10 driven):
#   - HTTPS-only listeners (TLS 1.3/1.2), HTTP→HTTPS 301 redirect.
#   - ALB deletion protection + drop_invalid_header_fields + access logs to S3.
#   - Tasks: readonly root FS, non-root user (1000:1000), all caps dropped.
#   - Restricted task egress: HTTPS to anywhere + DNS to VPC resolver only.
#   - CloudWatch log groups encrypted with a customer-managed KMS key.
#   - VPC flow logs (ALL traffic) to KMS-encrypted CloudWatch log group.
#   - CloudWatch alarms on ALB 5xx and unhealthy targets.
#
# Account-level prerequisites (NOT provisioned here, assumed enabled):
#   - AWS GuardDuty in this region.
#   - AWS Config + a CIS / SecurityHub conformance pack.
#   - CloudTrail organisation trail capturing management events.
#   - Inspector for ECR (continuous CVE scan; complements scan_on_push).
# =============================================================================

locals {
  services = {
    "impala-api"   = { container_port = 8080 }
    "impala-admin" = { container_port = 8080 }
  }
}

# --- Networking (singletons) ---

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "impala-vpc"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "impala-igw"
  }
}

data "aws_availability_zones" "this" {
  state = "available"
}

resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.this.names[count.index]

  # Public subnets host only the internet-facing ALBs and need public IPs.
  #trivy:ignore:AVD-AWS-0164
  map_public_ip_on_launch = true

  tags = {
    Name = "impala-public-${count.index}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = {
    Name = "impala-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- Private task networking (opt-in via var.private_tasks_enabled) ---
#
# Blast-radius / cost decision: with the default (off), tasks sit in the
# public subnets with assign_public_ip = true. Ingress is already restricted
# to the ALB SGs and egress to 443 + DNS, so the exposure is moderate — but a
# public IP on a task ENI is a direct-egress/exfiltration path and is flagged
# by every benchmark. Moving the tasks to private subnets requires NAT for
# ECR image pulls over 443 (this module has no VPC endpoints): a single NAT
# gateway (~USD 33/mo + data processing) was chosen over the alternative of
# 3 interface VPC endpoints (ecr.api, ecr.dkr, logs) + an S3 gateway endpoint
# — cheaper at low traffic but 4 new resources plus endpoint-SG complexity.
# Default-off so enabling the NAT spend stays an operator decision
# (../../impala.tf).

resource "aws_subnet" "private" {
  count             = var.private_tasks_enabled ? 2 : 0
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.this.names[count.index]

  tags = {
    Name = "impala-private-${count.index}"
  }
}

resource "aws_eip" "nat" {
  count  = var.private_tasks_enabled ? 1 : 0
  domain = "vpc"

  tags = {
    Name = "impala-nat-eip"
  }
}

resource "aws_nat_gateway" "this" {
  count         = var.private_tasks_enabled ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "impala-nat"
  }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "private" {
  count  = var.private_tasks_enabled ? 1 : 0
  vpc_id = aws_vpc.this.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[0].id
  }

  tags = {
    Name = "impala-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = var.private_tasks_enabled ? 2 : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# --- Security groups (per-service) ---

resource "aws_security_group" "alb" {
  for_each    = local.services
  name        = "${each.key}-alb"
  description = "Allow public HTTP/HTTPS to ${each.key} ALB"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTP from world (redirected to HTTPS by listener)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from world"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Open ALB egress is by design — the ALB forwards to task ENIs whose IPs
  # are dynamic (Fargate), so the target side cannot be pinned by CIDR.
  #trivy:ignore:AVD-AWS-0104
  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${each.key}-alb"
  }
}

resource "aws_security_group" "tasks" {
  for_each    = local.services
  name        = "${each.key}-tasks"
  description = "Allow container traffic from ${each.key} ALB; restricted egress"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "From ${each.key} ALB"
    from_port       = each.value.container_port
    to_port         = each.value.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb[each.key].id]
  }

  # Restricted egress: HTTPS to anywhere (ECR pulls, AWS APIs, external HTTPS)
  # plus DNS to the VPC resolver. Blocks SSH/SMTP/IRC/etc. exfiltration paths
  # and limits SSRF/RCE blast radius. The 0.0.0.0/0 on 443 is accepted:
  #trivy:ignore:AVD-AWS-0104
  egress {
    description = "HTTPS to anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS UDP to VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "DNS TCP to VPC resolver (fallback / large responses)"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${each.key}-tasks"
  }
}

# --- Load balancing (per-service) ---

# Internet-facing ALBs are the public entry points for impala-api and
# impala-admin — public by design.
#trivy:ignore:AVD-AWS-0053
resource "aws_lb" "this" {
  for_each           = local.services
  name               = each.key
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[each.key].id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = true
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = each.key
    enabled = true
  }

  tags = {
    Name = each.key
  }
}

resource "aws_lb_target_group" "this" {
  for_each    = local.services
  name        = each.key
  port        = each.value.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.this.id

  health_check {
    path                = "/"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    matcher             = "200-399"
  }

  tags = {
    Name = each.key
  }
}

resource "aws_lb_listener" "https" {
  for_each          = local.services
  load_balancer_arn = aws_lb.this[each.key].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[each.key].arn
  }

  lifecycle {
    precondition {
      condition     = var.certificate_arn != ""
      error_message = "var.impala_certificate_arn is required when impala_enabled = true (HTTPS-only listener)."
    }
  }
}

resource "aws_lb_listener" "http_redirect" {
  for_each          = local.services
  load_balancer_arn = aws_lb.this[each.key].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# --- IAM (singleton execution role; no task role for placeholder services) ---

resource "aws_iam_role" "execution" {
  name = "impala-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "impala-ecs-execution"
  }
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- Logging (per-service) ---

resource "aws_cloudwatch_log_group" "this" {
  for_each          = local.services
  name              = "/ecs/${each.key}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs.arn
}

# --- ECS cluster + task definitions + services ---

resource "aws_ecs_cluster" "this" {
  name = "impala"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "this" {
  for_each                 = local.services
  family                   = each.key
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  # NOTE: readonlyRootFilesystem = true means the image cannot write to "/".
  # Images that need scratch space must add `volumes` + `mountPoints` (e.g. a
  # tmpfs-backed volume) to the task definition.
  container_definitions = jsonencode([{
    name                   = each.key
    image                  = "${var.ecr_repository_urls[each.key]}:${var.container_image_tag}"
    essential              = true
    readonlyRootFilesystem = true
    user                   = "1000:1000"
    privileged             = false

    linuxParameters = {
      capabilities = {
        drop = ["ALL"]
      }
    }

    portMappings = [{
      containerPort = each.value.container_port
      protocol      = "tcp"
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.this[each.key].name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = each.key
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  for_each        = local.services
  name            = each.key
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this[each.key].arn
  launch_type     = "FARGATE"
  desired_count   = 1

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # Flipping private_tasks_enabled is an in-place update: a new deployment
  # rolls the tasks into the private subnets, no service replacement.
  network_configuration {
    subnets          = var.private_tasks_enabled ? aws_subnet.private[*].id : aws_subnet.public[*].id
    security_groups  = [aws_security_group.tasks[each.key].id]
    assign_public_ip = !var.private_tasks_enabled
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this[each.key].arn
    container_name   = each.key
    container_port   = each.value.container_port
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener.https]
}

# =============================================================================
# Security supporting infrastructure: KMS key, S3 access logs, VPC flow logs,
# CloudWatch alarms.
# =============================================================================

# --- KMS key for log encryption (singleton) ---

resource "aws_kms_key" "logs" {
  description             = "Encrypts impala CloudWatch log groups (app + flow logs)"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "impala-logs-key-policy"
    Statement = [
      {
        Sid       = "EnableRootAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsRegion"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:*"
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/impala-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# --- S3 bucket for ALB access logs (singleton) ---

data "aws_elb_service_account" "this" {}

resource "aws_s3_bucket" "alb_logs" {
  bucket_prefix = "impala-alb-logs-"
  force_destroy = false

  tags = {
    Name = "impala-alb-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ELB access-log delivery only supports SSE-S3 (AES256); the log-delivery
# service rejects SSE-KMS destination buckets, so a CMK is not an option.
#trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-after-90-days"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowELBToWrite"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_elb_service_account.this.id}:root"
      }
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.alb_logs.arn}/*"
    }]
  })
}

# --- VPC flow logs (singleton) ---

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/impala-flow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_iam_role" "flow_logs" {
  name = "impala-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "impala-flow-logs-write"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.this.id
}

# --- CloudWatch alarms (per-service) ---

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  for_each            = local.services
  alarm_name          = "${each.key}-alb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Elevated 5xx rate from ALB for ${each.key} (potential exploitation or degradation)"
  treat_missing_data  = "notBreaching"

  # Routed to the root ops topic when one is wired in; [] (no topic) keeps
  # the legacy console-only alarms.
  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    LoadBalancer = aws_lb.this[each.key].arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  for_each            = local.services
  alarm_name          = "${each.key}-unhealthy-targets"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "${each.key} target group has unhealthy targets"
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  dimensions = {
    LoadBalancer = aws_lb.this[each.key].arn_suffix
    TargetGroup  = aws_lb_target_group.this[each.key].arn_suffix
  }
}
