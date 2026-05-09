# =============================================================================
# Impala cluster — minimal Fargate stack for impala-api and impala-admin.
# Public-subnet-only networking (no NAT); two separate public ALBs (one per
# service); single task per service; pulls images from the ECR repos defined
# in ecr.tf (aws_ecr_repository.deploy["impala-api"|"impala-admin"]).
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
  impala_services = {
    "impala-api"   = { container_port = 8080 }
    "impala-admin" = { container_port = 8080 }
  }
}

# --- Networking (singletons, count-gated) ---

resource "aws_vpc" "impala" {
  count                = var.impala_enabled ? 1 : 0
  cidr_block           = var.impala_vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "impala-vpc"
  }
}

resource "aws_internet_gateway" "impala" {
  count  = var.impala_enabled ? 1 : 0
  vpc_id = aws_vpc.impala[0].id

  tags = {
    Name = "impala-igw"
  }
}

data "aws_availability_zones" "impala_available" {
  state = "available"
}

resource "aws_subnet" "impala_public" {
  count                   = var.impala_enabled ? 2 : 0
  vpc_id                  = aws_vpc.impala[0].id
  cidr_block              = cidrsubnet(var.impala_vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.impala_available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "impala-public-${count.index}"
  }
}

resource "aws_route_table" "impala_public" {
  count  = var.impala_enabled ? 1 : 0
  vpc_id = aws_vpc.impala[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.impala[0].id
  }

  tags = {
    Name = "impala-public-rt"
  }
}

resource "aws_route_table_association" "impala_public" {
  count          = var.impala_enabled ? 2 : 0
  subnet_id      = aws_subnet.impala_public[count.index].id
  route_table_id = aws_route_table.impala_public[0].id
}

# --- Security groups (per-service) ---

resource "aws_security_group" "impala_alb" {
  for_each    = var.impala_enabled ? local.impala_services : {}
  name        = "${each.key}-alb"
  description = "Allow public HTTP/HTTPS to ${each.key} ALB"
  vpc_id      = aws_vpc.impala[0].id

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

resource "aws_security_group" "impala_tasks" {
  for_each    = var.impala_enabled ? local.impala_services : {}
  name        = "${each.key}-tasks"
  description = "Allow container traffic from ${each.key} ALB; restricted egress"
  vpc_id      = aws_vpc.impala[0].id

  ingress {
    description     = "From ${each.key} ALB"
    from_port       = each.value.container_port
    to_port         = each.value.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.impala_alb[each.key].id]
  }

  # Restricted egress: HTTPS to anywhere (ECR pulls, AWS APIs, external HTTPS)
  # plus DNS to the VPC resolver. Blocks SSH/SMTP/IRC/etc. exfiltration paths
  # and limits SSRF/RCE blast radius.
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
    cidr_blocks = [var.impala_vpc_cidr]
  }

  egress {
    description = "DNS TCP to VPC resolver (fallback / large responses)"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.impala_vpc_cidr]
  }

  tags = {
    Name = "${each.key}-tasks"
  }
}

# --- Load balancing (per-service) ---

resource "aws_lb" "impala" {
  for_each           = var.impala_enabled ? local.impala_services : {}
  name               = each.key
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.impala_alb[each.key].id]
  subnets            = aws_subnet.impala_public[*].id

  enable_deletion_protection = true
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.impala_alb_logs[0].id
    prefix  = each.key
    enabled = true
  }

  tags = {
    Name = each.key
  }
}

resource "aws_lb_target_group" "impala" {
  for_each    = var.impala_enabled ? local.impala_services : {}
  name        = each.key
  port        = each.value.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.impala[0].id

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

resource "aws_lb_listener" "impala_https" {
  for_each          = var.impala_enabled ? local.impala_services : {}
  load_balancer_arn = aws_lb.impala[each.key].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.impala_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.impala[each.key].arn
  }

  lifecycle {
    precondition {
      condition     = !var.impala_enabled || var.impala_certificate_arn != ""
      error_message = "var.impala_certificate_arn is required when impala_enabled = true (HTTPS-only listener)."
    }
  }
}

resource "aws_lb_listener" "impala_http_redirect" {
  for_each          = var.impala_enabled ? local.impala_services : {}
  load_balancer_arn = aws_lb.impala[each.key].arn
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

resource "aws_iam_role" "impala_execution" {
  count = var.impala_enabled ? 1 : 0
  name  = "impala-ecs-execution"

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

resource "aws_iam_role_policy_attachment" "impala_execution_managed" {
  count      = var.impala_enabled ? 1 : 0
  role       = aws_iam_role.impala_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- Logging (per-service) ---

resource "aws_cloudwatch_log_group" "impala" {
  for_each          = var.impala_enabled ? local.impala_services : {}
  name              = "/ecs/${each.key}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.impala_logs[0].arn
}

# --- ECS cluster + task definitions + services ---

resource "aws_ecs_cluster" "impala" {
  count = var.impala_enabled ? 1 : 0
  name  = "impala"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "impala" {
  for_each                 = var.impala_enabled ? local.impala_services : {}
  family                   = each.key
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.impala_execution[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  # NOTE: readonlyRootFilesystem = true means the image cannot write to "/".
  # Images that need scratch space must add `volumes` + `mountPoints` (e.g. a
  # tmpfs-backed volume) to the task definition.
  container_definitions = jsonencode([{
    name                   = each.key
    image                  = "${aws_ecr_repository.deploy[each.key].repository_url}:${var.container_image_tag}"
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
        "awslogs-group"         = aws_cloudwatch_log_group.impala[each.key].name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = each.key
      }
    }
  }])
}

resource "aws_ecs_service" "impala" {
  for_each        = var.impala_enabled ? local.impala_services : {}
  name            = each.key
  cluster         = aws_ecs_cluster.impala[0].id
  task_definition = aws_ecs_task_definition.impala[each.key].arn
  launch_type     = "FARGATE"
  desired_count   = 1

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.impala_public[*].id
    security_groups  = [aws_security_group.impala_tasks[each.key].id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.impala[each.key].arn
    container_name   = each.key
    container_port   = each.value.container_port
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener.impala_https]
}

# =============================================================================
# Security supporting infrastructure: KMS key, S3 access logs, VPC flow logs,
# CloudWatch alarms.
# =============================================================================

# --- KMS key for log encryption (singleton) ---

resource "aws_kms_key" "impala_logs" {
  count                   = var.impala_enabled ? 1 : 0
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
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
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
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "impala_logs" {
  count         = var.impala_enabled ? 1 : 0
  name          = "alias/impala-logs"
  target_key_id = aws_kms_key.impala_logs[0].key_id
}

# --- S3 bucket for ALB access logs (singleton) ---

data "aws_elb_service_account" "main" {
  count = var.impala_enabled ? 1 : 0
}

resource "aws_s3_bucket" "impala_alb_logs" {
  count         = var.impala_enabled ? 1 : 0
  bucket_prefix = "impala-alb-logs-"
  force_destroy = false

  tags = {
    Name = "impala-alb-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "impala_alb_logs" {
  count                   = var.impala_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.impala_alb_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "impala_alb_logs" {
  count  = var.impala_enabled ? 1 : 0
  bucket = aws_s3_bucket.impala_alb_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "impala_alb_logs" {
  count  = var.impala_enabled ? 1 : 0
  bucket = aws_s3_bucket.impala_alb_logs[0].id

  rule {
    id     = "expire-after-90-days"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_policy" "impala_alb_logs" {
  count  = var.impala_enabled ? 1 : 0
  bucket = aws_s3_bucket.impala_alb_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowELBToWrite"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_elb_service_account.main[0].id}:root"
      }
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.impala_alb_logs[0].arn}/*"
    }]
  })
}

# --- VPC flow logs (singleton) ---

resource "aws_cloudwatch_log_group" "impala_vpc_flow_logs" {
  count             = var.impala_enabled ? 1 : 0
  name              = "/aws/vpc/impala-flow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.impala_logs[0].arn
}

resource "aws_iam_role" "impala_flow_logs" {
  count = var.impala_enabled ? 1 : 0
  name  = "impala-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "impala_flow_logs" {
  count = var.impala_enabled ? 1 : 0
  name  = "impala-flow-logs-write"
  role  = aws_iam_role.impala_flow_logs[0].id

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
      Resource = "${aws_cloudwatch_log_group.impala_vpc_flow_logs[0].arn}:*"
    }]
  })
}

resource "aws_flow_log" "impala" {
  count           = var.impala_enabled ? 1 : 0
  iam_role_arn    = aws_iam_role.impala_flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.impala_vpc_flow_logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.impala[0].id
}

# --- CloudWatch alarms (per-service) ---

resource "aws_cloudwatch_metric_alarm" "impala_alb_5xx" {
  for_each            = var.impala_enabled ? local.impala_services : {}
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

  dimensions = {
    LoadBalancer = aws_lb.impala[each.key].arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "impala_unhealthy_targets" {
  for_each            = var.impala_enabled ? local.impala_services : {}
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

  dimensions = {
    LoadBalancer = aws_lb.impala[each.key].arn_suffix
    TargetGroup  = aws_lb_target_group.impala[each.key].arn_suffix
  }
}
