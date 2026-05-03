# =============================================================================
# Live ECS Cluster Infrastructure
# All resources conditional on var.live_enabled
# Deploys an environment pointing at Stellar pubnet (mainnet) in the same region
# =============================================================================

# --- Live Availability Zones ---

data "aws_availability_zones" "live" {
  count = var.live_enabled ? 1 : 0
  state = "available"
}

# =============================================================================
# Live VPC + Networking (Single AZ)
# =============================================================================

resource "aws_vpc" "live" {
  count = var.live_enabled ? 1 : 0

  cidr_block           = var.live_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-vpc-live"
  }
}

resource "aws_subnet" "live_public" {
  count = var.live_enabled ? 1 : 0

  vpc_id            = aws_vpc.live[0].id
  cidr_block        = cidrsubnet(var.live_vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.live[0].names[count.index]

  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-live-public-${count.index}"
  }
}

resource "aws_subnet" "live_private" {
  count = var.live_enabled ? 1 : 0

  vpc_id            = aws_vpc.live[0].id
  cidr_block        = cidrsubnet(var.live_vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.live[0].names[count.index]

  tags = {
    Name = "${local.name_prefix}-live-private-${count.index}"
  }
}

resource "aws_internet_gateway" "live" {
  count = var.live_enabled ? 1 : 0

  vpc_id = aws_vpc.live[0].id

  tags = {
    Name = "${local.name_prefix}-igw-live"
  }
}

resource "aws_eip" "live_nat" {
  count = var.live_enabled ? 1 : 0

  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-live-nat-eip-${count.index}"
  }
}

resource "aws_nat_gateway" "live" {
  count = var.live_enabled ? 1 : 0

  allocation_id = aws_eip.live_nat[count.index].id
  subnet_id     = aws_subnet.live_public[count.index].id

  tags = {
    Name = "${local.name_prefix}-live-nat-${count.index}"
  }

  depends_on = [aws_internet_gateway.live]
}

resource "aws_route_table" "live_public" {
  count = var.live_enabled ? 1 : 0

  vpc_id = aws_vpc.live[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.live[0].id
  }

  tags = {
    Name = "${local.name_prefix}-live-public-rt"
  }
}

resource "aws_route_table_association" "live_public" {
  count = var.live_enabled ? 1 : 0

  subnet_id      = aws_subnet.live_public[count.index].id
  route_table_id = aws_route_table.live_public[0].id
}

resource "aws_route_table" "live_private" {
  count = var.live_enabled ? 1 : 0

  vpc_id = aws_vpc.live[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.live[count.index].id
  }

  tags = {
    Name = "${local.name_prefix}-live-private-rt-${count.index}"
  }
}

resource "aws_route_table_association" "live_private" {
  count = var.live_enabled ? 1 : 0

  subnet_id      = aws_subnet.live_private[count.index].id
  route_table_id = aws_route_table.live_private[count.index].id
}

# =============================================================================
# Live Security Groups
# =============================================================================

resource "aws_security_group" "live_alb" {
  count = var.live_enabled ? 1 : 0

  name_prefix = "${local.name_prefix}-live-alb-"
  description = "Allow HTTP/HTTPS inbound to live ALB"
  vpc_id      = aws_vpc.live[0].id

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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-live-alb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "live_ecs_tasks" {
  count = var.live_enabled ? 1 : 0

  name_prefix = "${local.name_prefix}-live-ecs-"
  description = "Allow inbound from live ALB, outbound all"
  vpc_id      = aws_vpc.live[0].id

  ingress {
    description     = "From live ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.live_alb[0].id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-live-ecs-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "live_rds" {
  count = var.live_enabled ? 1 : 0

  name_prefix = "${local.name_prefix}-live-rds-"
  description = "Allow PostgreSQL from live ECS tasks"
  vpc_id      = aws_vpc.live[0].id

  ingress {
    description     = "PostgreSQL from live ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.live_ecs_tasks[0].id]
  }

  tags = {
    Name = "${local.name_prefix}-live-rds-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "live_redis" {
  count = var.live_enabled ? 1 : 0

  name_prefix = "${local.name_prefix}-live-redis-"
  description = "Allow Redis from live ECS tasks"
  vpc_id      = aws_vpc.live[0].id

  ingress {
    description     = "Redis from live ECS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.live_ecs_tasks[0].id]
  }

  tags = {
    Name = "${local.name_prefix}-live-redis-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# Live ALB
# =============================================================================

resource "aws_lb" "live" {
  count = var.live_enabled ? 1 : 0

  name               = "${local.name_prefix}-alb-live"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.live_alb[0].id]
  subnets            = aws_subnet.live_public[*].id

  tags = {
    Name = "${local.name_prefix}-alb-live"
  }
}

resource "aws_lb_target_group" "live_server" {
  count = var.live_enabled ? 1 : 0

  name        = "${local.name_prefix}-tg-live"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.live[0].id
  target_type = "ip"

  health_check {
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = {
    Name = "${local.name_prefix}-tg-live"
  }
}

resource "aws_lb_listener" "live_http" {
  count = var.live_enabled ? 1 : 0

  load_balancer_arn = aws_lb.live[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.live_server[0].arn
  }
}

resource "aws_lb_listener" "live_https" {
  count = var.live_enabled && var.live_certificate_arn != "" ? 1 : 0

  load_balancer_arn = aws_lb.live[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.live_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.live_server[0].arn
  }
}

# =============================================================================
# Live ElastiCache (Single Node, No Failover)
# =============================================================================

resource "aws_elasticache_subnet_group" "live" {
  count = var.live_enabled ? 1 : 0

  name       = "${local.name_prefix}-redis-subnet-live"
  subnet_ids = aws_subnet.live_private[*].id

  tags = {
    Name = "${local.name_prefix}-redis-subnet-live"
  }
}

resource "aws_elasticache_replication_group" "live" {
  count = var.live_enabled ? 1 : 0

  replication_group_id = "${local.name_prefix}-redis-live"
  description          = "Live Redis replication group for ${local.name_prefix}"

  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.live_redis_node_type
  num_cache_clusters   = 1
  port                 = 6379
  parameter_group_name = "default.redis7"

  subnet_group_name  = aws_elasticache_subnet_group.live[0].name
  security_group_ids = [aws_security_group.live_redis[0].id]

  automatic_failover_enabled = false
  multi_az_enabled           = false

  at_rest_encryption_enabled = true
  transit_encryption_enabled = false

  tags = {
    Name = "${local.name_prefix}-redis-live"
  }
}

# =============================================================================
# Live RDS (Independent, Single-AZ)
# =============================================================================

resource "random_password" "live_rds_password" {
  count = var.live_enabled ? 1 : 0

  length  = 32
  special = false
}

resource "aws_kms_key" "live_rds" {
  count = var.live_enabled ? 1 : 0

  description             = "KMS key for live RDS encryption - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-rds-kms-live"
  }
}

resource "aws_db_subnet_group" "live" {
  count = var.live_enabled ? 1 : 0

  name       = "${local.name_prefix}-db-subnet-live"
  subnet_ids = aws_subnet.live_private[*].id

  tags = {
    Name = "${local.name_prefix}-db-subnet-live"
  }
}

resource "aws_db_instance" "live" {
  count = var.live_enabled ? 1 : 0

  identifier     = "${local.name_prefix}-db-live"
  engine         = "postgres"
  engine_version = var.rds_engine_version
  instance_class = var.live_rds_instance_class

  allocated_storage = 20
  storage_encrypted = true
  kms_key_id        = aws_kms_key.live_rds[0].arn

  db_name  = "impala"
  username = "impala_admin"
  password = random_password.live_rds_password[0].result

  db_subnet_group_name   = aws_db_subnet_group.live[0].name
  vpc_security_group_ids = [aws_security_group.live_rds[0].id]

  multi_az            = false
  publicly_accessible = false

  skip_final_snapshot = true
  deletion_protection = false

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.live_rds[0].arn

  backup_retention_period = 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  apply_immediately = true

  tags = {
    Name = "${local.name_prefix}-db-live"
  }
}

# =============================================================================
# Live SNS/SQS (Worker Queue)
# =============================================================================

resource "aws_sns_topic" "live_jobs" {
  count = var.live_enabled ? 1 : 0

  name = "${local.name_prefix}-jobs-live"

  tags = {
    Name = "${local.name_prefix}-jobs-live"
  }
}

resource "aws_sqs_queue" "live_worker_dlq" {
  count = var.live_enabled ? 1 : 0

  name                      = "${local.name_prefix}-worker-dlq-live"
  message_retention_seconds = 1209600

  tags = {
    Name = "${local.name_prefix}-worker-dlq-live"
  }
}

resource "aws_sqs_queue" "live_worker" {
  count = var.live_enabled ? 1 : 0

  name                       = "${local.name_prefix}-worker-live"
  visibility_timeout_seconds = var.sqs_visibility_timeout_seconds
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.live_worker_dlq[0].arn
    maxReceiveCount     = var.sqs_max_receive_count
  })

  tags = {
    Name = "${local.name_prefix}-worker-live"
  }
}

resource "aws_sns_topic_subscription" "live_worker" {
  count = var.live_enabled ? 1 : 0

  topic_arn = aws_sns_topic.live_jobs[0].arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.live_worker[0].arn
}

resource "aws_sqs_queue_policy" "live_worker" {
  count = var.live_enabled ? 1 : 0

  queue_url = aws_sqs_queue.live_worker[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSNSSend"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.live_worker[0].arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.live_jobs[0].arn
          }
        }
      }
    ]
  })
}

# =============================================================================
# Live Secrets Manager
# =============================================================================

resource "aws_secretsmanager_secret" "live_database_url" {
  count = var.live_enabled ? 1 : 0

  name        = "${local.name_prefix}-database-url-live"
  description = "DATABASE_URL for live impala-bridge"
}

resource "aws_secretsmanager_secret_version" "live_database_url" {
  count = var.live_enabled ? 1 : 0

  secret_id     = aws_secretsmanager_secret.live_database_url[0].id
  secret_string = "postgresql://impala_admin:${random_password.live_rds_password[0].result}@${aws_db_instance.live[0].endpoint}/impala"
}

resource "aws_secretsmanager_secret" "live_jwt_secret" {
  count = var.live_enabled ? 1 : 0

  name        = "${local.name_prefix}-jwt-secret-live"
  description = "JWT signing secret for live impala-bridge"
}

resource "aws_secretsmanager_secret_version" "live_jwt_secret" {
  count = var.live_enabled ? 1 : 0

  secret_id     = aws_secretsmanager_secret.live_jwt_secret[0].id
  secret_string = var.live_jwt_secret
}

# =============================================================================
# Live IAM Roles
# =============================================================================

resource "aws_iam_role" "live_ecs_task_execution" {
  count = var.live_enabled ? 1 : 0

  name = "${local.name_prefix}-ecs-exec-live"

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

resource "aws_iam_role_policy_attachment" "live_ecs_task_execution" {
  count = var.live_enabled ? 1 : 0

  role       = aws_iam_role.live_ecs_task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "live_execution_secrets" {
  count = var.live_enabled ? 1 : 0

  name = "${local.name_prefix}-exec-secrets-live"
  role = aws_iam_role.live_ecs_task_execution[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = [
          aws_secretsmanager_secret.live_database_url[0].arn,
          aws_secretsmanager_secret.live_jwt_secret[0].arn,
        ]
      }
    ]
  })
}

resource "aws_iam_role" "live_ecs_task" {
  count = var.live_enabled ? 1 : 0

  name = "${local.name_prefix}-ecs-task-live"

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

resource "aws_iam_role_policy" "live_ecs_task_permissions" {
  count = var.live_enabled ? 1 : 0

  name = "${local.name_prefix}-task-permissions-live"
  role = aws_iam_role.live_ecs_task[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
        ]
        Resource = aws_sqs_queue.live_worker[0].arn
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.live_jobs[0].arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail",
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# Live CloudWatch Log Groups
# =============================================================================

resource "aws_cloudwatch_log_group" "live_server" {
  count = var.live_enabled ? 1 : 0

  name              = "/ecs/${local.name_prefix}-server-live"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "live_worker" {
  count = var.live_enabled ? 1 : 0

  name              = "/ecs/${local.name_prefix}-worker-live"
  retention_in_days = 30
}

# =============================================================================
# Live ECS Cluster + Services
# =============================================================================

resource "aws_ecs_cluster" "live" {
  count = var.live_enabled ? 1 : 0

  name = "${local.name_prefix}-cluster-live"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${local.name_prefix}-cluster-live"
  }
}

# Live Server Task Definition
resource "aws_ecs_task_definition" "live_server" {
  count = var.live_enabled ? 1 : 0

  family                   = "${local.name_prefix}-server-live"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.live_server_cpu
  memory                   = var.live_server_memory
  execution_role_arn       = aws_iam_role.live_ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.live_ecs_task[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode([
    {
      name      = "impala-bridge-server"
      image     = "${aws_ecr_repository.bridge.repository_url}:${var.container_image_tag}"
      essential = true

      readonlyRootFilesystem = true
      user                   = "1000:1000"

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "RUN_MODE", value = "server" },
        { name = "SERVICE_ADDRESS", value = "0.0.0.0:8080" },
        { name = "REDIS_URL", value = "redis://${aws_elasticache_replication_group.live[0].primary_endpoint_address}:6379" },
        { name = "STELLAR_NETWORK", value = "pubnet" },
        { name = "STELLAR_HORIZON_URL", value = "https://horizon.stellar.org" },
        { name = "STELLAR_RPC_URL", value = "https://soroban-rpc.stellar.org" },
        { name = "STELLAR_NETWORK_PASSPHRASE", value = "Public Global Stellar Network ; September 2015" },
        { name = "DEBUG_MODE", value = "false" },
        { name = "SNS_TOPIC_ARN", value = aws_sns_topic.live_jobs[0].arn },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
        { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.live_database_url[0].arn
        },
        {
          name      = "JWT_SECRET"
          valueFrom = aws_secretsmanager_secret.live_jwt_secret[0].arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.live_server[0].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "server"
        }
      }
    }
  ])
}

# Live Worker Task Definition
resource "aws_ecs_task_definition" "live_worker" {
  count = var.live_enabled ? 1 : 0

  family                   = "${local.name_prefix}-worker-live"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.live_worker_cpu
  memory                   = var.live_worker_memory
  execution_role_arn       = aws_iam_role.live_ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.live_ecs_task[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode([
    {
      name      = "impala-bridge-worker"
      image     = "${aws_ecr_repository.bridge.repository_url}:${var.container_image_tag}"
      essential = true

      readonlyRootFilesystem = true
      user                   = "1000:1000"

      environment = [
        { name = "RUN_MODE", value = "worker" },
        { name = "SQS_QUEUE_URL", value = aws_sqs_queue.live_worker[0].url },
        { name = "REDIS_URL", value = "redis://${aws_elasticache_replication_group.live[0].primary_endpoint_address}:6379" },
        { name = "STELLAR_NETWORK", value = "pubnet" },
        { name = "STELLAR_HORIZON_URL", value = "https://horizon.stellar.org" },
        { name = "STELLAR_RPC_URL", value = "https://soroban-rpc.stellar.org" },
        { name = "STELLAR_NETWORK_PASSPHRASE", value = "Public Global Stellar Network ; September 2015" },
        { name = "DEBUG_MODE", value = "false" },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
        { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.live_database_url[0].arn
        },
        {
          name      = "JWT_SECRET"
          valueFrom = aws_secretsmanager_secret.live_jwt_secret[0].arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.live_worker[0].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "worker"
        }
      }
    }
  ])
}

# Live Server ECS Service
resource "aws_ecs_service" "live_server" {
  count = var.live_enabled ? 1 : 0

  name            = "${local.name_prefix}-server-live"
  cluster         = aws_ecs_cluster.live[0].id
  task_definition = aws_ecs_task_definition.live_server[0].arn
  desired_count   = var.live_server_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.live_private[*].id
    security_groups  = [aws_security_group.live_ecs_tasks[0].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.live_server[0].arn
    container_name   = "impala-bridge-server"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener.live_http]
}

# Live Worker ECS Service
resource "aws_ecs_service" "live_worker" {
  count = var.live_enabled ? 1 : 0

  name            = "${local.name_prefix}-worker-live"
  cluster         = aws_ecs_cluster.live[0].id
  task_definition = aws_ecs_task_definition.live_worker[0].arn
  desired_count   = var.live_worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.live_private[*].id
    security_groups  = [aws_security_group.live_ecs_tasks[0].id]
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
