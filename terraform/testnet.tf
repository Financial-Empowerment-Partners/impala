# =============================================================================
# Testnet ECS Cluster Infrastructure
# All resources conditional on var.testnet_enabled
# Deploys a separate environment pointing at Stellar testnet (same region)
# =============================================================================

# --- Testnet Availability Zones ---

data "aws_availability_zones" "testnet" {
  count = var.testnet_enabled ? 1 : 0
  state = "available"
}

# =============================================================================
# Testnet VPC + Networking (Single AZ)
# =============================================================================

resource "aws_vpc" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  cidr_block           = var.testnet_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-vpc-testnet"
  }
}

resource "aws_subnet" "testnet_public" {
  count = var.testnet_enabled ? 1 : 0

  vpc_id            = aws_vpc.testnet[0].id
  cidr_block        = cidrsubnet(var.testnet_vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.testnet[0].names[count.index]

  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-testnet-public-${count.index}"
  }
}

resource "aws_subnet" "testnet_private" {
  count = var.testnet_enabled ? 1 : 0

  vpc_id            = aws_vpc.testnet[0].id
  cidr_block        = cidrsubnet(var.testnet_vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.testnet[0].names[count.index]

  tags = {
    Name = "${local.name_prefix}-testnet-private-${count.index}"
  }
}

resource "aws_internet_gateway" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  vpc_id = aws_vpc.testnet[0].id

  tags = {
    Name = "${local.name_prefix}-igw-testnet"
  }
}

resource "aws_eip" "testnet_nat" {
  count = var.testnet_enabled ? 1 : 0

  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-testnet-nat-eip-${count.index}"
  }
}

resource "aws_nat_gateway" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  allocation_id = aws_eip.testnet_nat[count.index].id
  subnet_id     = aws_subnet.testnet_public[count.index].id

  tags = {
    Name = "${local.name_prefix}-testnet-nat-${count.index}"
  }

  depends_on = [aws_internet_gateway.testnet]
}

resource "aws_route_table" "testnet_public" {
  count = var.testnet_enabled ? 1 : 0

  vpc_id = aws_vpc.testnet[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.testnet[0].id
  }

  tags = {
    Name = "${local.name_prefix}-testnet-public-rt"
  }
}

resource "aws_route_table_association" "testnet_public" {
  count = var.testnet_enabled ? 1 : 0

  subnet_id      = aws_subnet.testnet_public[count.index].id
  route_table_id = aws_route_table.testnet_public[0].id
}

resource "aws_route_table" "testnet_private" {
  count = var.testnet_enabled ? 1 : 0

  vpc_id = aws_vpc.testnet[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.testnet[count.index].id
  }

  tags = {
    Name = "${local.name_prefix}-testnet-private-rt-${count.index}"
  }
}

resource "aws_route_table_association" "testnet_private" {
  count = var.testnet_enabled ? 1 : 0

  subnet_id      = aws_subnet.testnet_private[count.index].id
  route_table_id = aws_route_table.testnet_private[count.index].id
}

# =============================================================================
# Testnet Security Groups
# =============================================================================

resource "aws_security_group" "testnet_alb" {
  count = var.testnet_enabled ? 1 : 0

  name_prefix = "${local.name_prefix}-testnet-alb-"
  description = "Allow HTTP/HTTPS inbound to testnet ALB"
  vpc_id      = aws_vpc.testnet[0].id

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
    Name = "${local.name_prefix}-testnet-alb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "testnet_ecs_tasks" {
  count = var.testnet_enabled ? 1 : 0

  name_prefix = "${local.name_prefix}-testnet-ecs-"
  description = "Allow inbound from testnet ALB, outbound all"
  vpc_id      = aws_vpc.testnet[0].id

  ingress {
    description     = "From testnet ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.testnet_alb[0].id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-testnet-ecs-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "testnet_rds" {
  count = var.testnet_enabled ? 1 : 0

  name_prefix = "${local.name_prefix}-testnet-rds-"
  description = "Allow PostgreSQL from testnet ECS tasks"
  vpc_id      = aws_vpc.testnet[0].id

  ingress {
    description     = "PostgreSQL from testnet ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.testnet_ecs_tasks[0].id]
  }

  tags = {
    Name = "${local.name_prefix}-testnet-rds-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "testnet_redis" {
  count = var.testnet_enabled ? 1 : 0

  name_prefix = "${local.name_prefix}-testnet-redis-"
  description = "Allow Redis from testnet ECS tasks"
  vpc_id      = aws_vpc.testnet[0].id

  ingress {
    description     = "Redis from testnet ECS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.testnet_ecs_tasks[0].id]
  }

  tags = {
    Name = "${local.name_prefix}-testnet-redis-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# Testnet ALB
# =============================================================================

resource "aws_lb" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  name               = "${local.name_prefix}-alb-testnet"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.testnet_alb[0].id]
  subnets            = aws_subnet.testnet_public[*].id

  tags = {
    Name = "${local.name_prefix}-alb-testnet"
  }
}

resource "aws_lb_target_group" "testnet_server" {
  count = var.testnet_enabled ? 1 : 0

  name        = "${local.name_prefix}-tg-testnet"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.testnet[0].id
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
    Name = "${local.name_prefix}-tg-testnet"
  }
}

resource "aws_lb_listener" "testnet_http" {
  count = var.testnet_enabled ? 1 : 0

  load_balancer_arn = aws_lb.testnet[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.testnet_server[0].arn
  }
}

resource "aws_lb_listener" "testnet_https" {
  count = var.testnet_enabled && var.testnet_certificate_arn != "" ? 1 : 0

  load_balancer_arn = aws_lb.testnet[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.testnet_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.testnet_server[0].arn
  }
}

# =============================================================================
# Testnet ElastiCache (Single Node, No Failover)
# =============================================================================

resource "aws_elasticache_subnet_group" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  name       = "${local.name_prefix}-redis-subnet-testnet"
  subnet_ids = aws_subnet.testnet_private[*].id

  tags = {
    Name = "${local.name_prefix}-redis-subnet-testnet"
  }
}

resource "aws_elasticache_replication_group" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  replication_group_id = "${local.name_prefix}-redis-testnet"
  description          = "Testnet Redis replication group for ${local.name_prefix}"

  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.testnet_redis_node_type
  num_cache_clusters   = 1
  port                 = 6379
  parameter_group_name = "default.redis7"

  subnet_group_name  = aws_elasticache_subnet_group.testnet[0].name
  security_group_ids = [aws_security_group.testnet_redis[0].id]

  automatic_failover_enabled = false
  multi_az_enabled           = false

  at_rest_encryption_enabled = true
  transit_encryption_enabled = false

  tags = {
    Name = "${local.name_prefix}-redis-testnet"
  }
}

# =============================================================================
# Testnet RDS (Independent, Single-AZ)
# =============================================================================

resource "random_password" "testnet_rds_password" {
  count = var.testnet_enabled ? 1 : 0

  length  = 32
  special = false
}

resource "aws_kms_key" "testnet_rds" {
  count = var.testnet_enabled ? 1 : 0

  description             = "KMS key for testnet RDS encryption - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-rds-kms-testnet"
  }
}

resource "aws_db_subnet_group" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  name       = "${local.name_prefix}-db-subnet-testnet"
  subnet_ids = aws_subnet.testnet_private[*].id

  tags = {
    Name = "${local.name_prefix}-db-subnet-testnet"
  }
}

resource "aws_db_instance" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  identifier     = "${local.name_prefix}-db-testnet"
  engine         = "postgres"
  engine_version = var.rds_engine_version
  instance_class = var.testnet_rds_instance_class

  allocated_storage = 20
  storage_encrypted = true
  kms_key_id        = aws_kms_key.testnet_rds[0].arn

  db_name  = "impala"
  username = "impala_admin"
  password = random_password.testnet_rds_password[0].result

  db_subnet_group_name   = aws_db_subnet_group.testnet[0].name
  vpc_security_group_ids = [aws_security_group.testnet_rds[0].id]

  multi_az            = false
  publicly_accessible = false

  skip_final_snapshot = true
  deletion_protection = false

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.testnet_rds[0].arn

  backup_retention_period = 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  apply_immediately = true

  tags = {
    Name = "${local.name_prefix}-db-testnet"
  }
}

# =============================================================================
# Testnet SNS/SQS (Worker Queue)
# =============================================================================

resource "aws_sns_topic" "testnet_jobs" {
  count = var.testnet_enabled ? 1 : 0

  name = "${local.name_prefix}-jobs-testnet"

  tags = {
    Name = "${local.name_prefix}-jobs-testnet"
  }
}

resource "aws_sqs_queue" "testnet_worker_dlq" {
  count = var.testnet_enabled ? 1 : 0

  name                      = "${local.name_prefix}-worker-dlq-testnet"
  message_retention_seconds = 1209600

  tags = {
    Name = "${local.name_prefix}-worker-dlq-testnet"
  }
}

resource "aws_sqs_queue" "testnet_worker" {
  count = var.testnet_enabled ? 1 : 0

  name                       = "${local.name_prefix}-worker-testnet"
  visibility_timeout_seconds = var.sqs_visibility_timeout_seconds
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.testnet_worker_dlq[0].arn
    maxReceiveCount     = var.sqs_max_receive_count
  })

  tags = {
    Name = "${local.name_prefix}-worker-testnet"
  }
}

resource "aws_sns_topic_subscription" "testnet_worker" {
  count = var.testnet_enabled ? 1 : 0

  topic_arn = aws_sns_topic.testnet_jobs[0].arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.testnet_worker[0].arn
}

resource "aws_sqs_queue_policy" "testnet_worker" {
  count = var.testnet_enabled ? 1 : 0

  queue_url = aws_sqs_queue.testnet_worker[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSNSSend"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.testnet_worker[0].arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.testnet_jobs[0].arn
          }
        }
      }
    ]
  })
}

# =============================================================================
# Testnet Secrets Manager
# =============================================================================

resource "aws_secretsmanager_secret" "testnet_database_url" {
  count = var.testnet_enabled ? 1 : 0

  name        = "${local.name_prefix}-database-url-testnet"
  description = "DATABASE_URL for testnet impala-bridge"
}

resource "aws_secretsmanager_secret_version" "testnet_database_url" {
  count = var.testnet_enabled ? 1 : 0

  secret_id     = aws_secretsmanager_secret.testnet_database_url[0].id
  secret_string = "postgresql://impala_admin:${random_password.testnet_rds_password[0].result}@${aws_db_instance.testnet[0].endpoint}/impala"
}

resource "aws_secretsmanager_secret" "testnet_jwt_secret" {
  count = var.testnet_enabled ? 1 : 0

  name        = "${local.name_prefix}-jwt-secret-testnet"
  description = "JWT signing secret for testnet impala-bridge"
}

resource "aws_secretsmanager_secret_version" "testnet_jwt_secret" {
  count = var.testnet_enabled ? 1 : 0

  secret_id     = aws_secretsmanager_secret.testnet_jwt_secret[0].id
  secret_string = var.testnet_jwt_secret
}

# =============================================================================
# Testnet IAM Roles
# =============================================================================

resource "aws_iam_role" "testnet_ecs_task_execution" {
  count = var.testnet_enabled ? 1 : 0

  name = "${local.name_prefix}-ecs-exec-testnet"

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

resource "aws_iam_role_policy_attachment" "testnet_ecs_task_execution" {
  count = var.testnet_enabled ? 1 : 0

  role       = aws_iam_role.testnet_ecs_task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "testnet_execution_secrets" {
  count = var.testnet_enabled ? 1 : 0

  name = "${local.name_prefix}-exec-secrets-testnet"
  role = aws_iam_role.testnet_ecs_task_execution[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = [
          aws_secretsmanager_secret.testnet_database_url[0].arn,
          aws_secretsmanager_secret.testnet_jwt_secret[0].arn,
        ]
      }
    ]
  })
}

resource "aws_iam_role" "testnet_ecs_task" {
  count = var.testnet_enabled ? 1 : 0

  name = "${local.name_prefix}-ecs-task-testnet"

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

resource "aws_iam_role_policy" "testnet_ecs_task_permissions" {
  count = var.testnet_enabled ? 1 : 0

  name = "${local.name_prefix}-task-permissions-testnet"
  role = aws_iam_role.testnet_ecs_task[0].id

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
        Resource = aws_sqs_queue.testnet_worker[0].arn
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.testnet_jobs[0].arn
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
# Testnet CloudWatch Log Groups
# =============================================================================

resource "aws_cloudwatch_log_group" "testnet_server" {
  count = var.testnet_enabled ? 1 : 0

  name              = "/ecs/${local.name_prefix}-server-testnet"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "testnet_worker" {
  count = var.testnet_enabled ? 1 : 0

  name              = "/ecs/${local.name_prefix}-worker-testnet"
  retention_in_days = 30
}

# =============================================================================
# Testnet ECS Cluster + Services
# =============================================================================

resource "aws_ecs_cluster" "testnet" {
  count = var.testnet_enabled ? 1 : 0

  name = "${local.name_prefix}-cluster-testnet"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${local.name_prefix}-cluster-testnet"
  }
}

# Testnet Server Task Definition
resource "aws_ecs_task_definition" "testnet_server" {
  count = var.testnet_enabled ? 1 : 0

  family                   = "${local.name_prefix}-server-testnet"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.testnet_server_cpu
  memory                   = var.testnet_server_memory
  execution_role_arn       = aws_iam_role.testnet_ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.testnet_ecs_task[0].arn

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
        { name = "REDIS_URL", value = "redis://${aws_elasticache_replication_group.testnet[0].primary_endpoint_address}:6379" },
        { name = "STELLAR_NETWORK", value = "testnet" },
        { name = "STELLAR_HORIZON_URL", value = "https://horizon-testnet.stellar.org" },
        { name = "STELLAR_RPC_URL", value = "https://soroban-testnet.stellar.org" },
        { name = "SOROBAN_CONTRACT_ID", value = var.testnet_soroban_contract_id },
        { name = "DEBUG_MODE", value = "true" },
        { name = "SNS_TOPIC_ARN", value = aws_sns_topic.testnet_jobs[0].arn },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
        { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.testnet_database_url[0].arn
        },
        {
          name      = "JWT_SECRET"
          valueFrom = aws_secretsmanager_secret.testnet_jwt_secret[0].arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.testnet_server[0].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "server"
        }
      }
    }
  ])
}

# Testnet Worker Task Definition
resource "aws_ecs_task_definition" "testnet_worker" {
  count = var.testnet_enabled ? 1 : 0

  family                   = "${local.name_prefix}-worker-testnet"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.testnet_worker_cpu
  memory                   = var.testnet_worker_memory
  execution_role_arn       = aws_iam_role.testnet_ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.testnet_ecs_task[0].arn

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
        { name = "SQS_QUEUE_URL", value = aws_sqs_queue.testnet_worker[0].url },
        { name = "REDIS_URL", value = "redis://${aws_elasticache_replication_group.testnet[0].primary_endpoint_address}:6379" },
        { name = "STELLAR_NETWORK", value = "testnet" },
        { name = "STELLAR_HORIZON_URL", value = "https://horizon-testnet.stellar.org" },
        { name = "STELLAR_RPC_URL", value = "https://soroban-testnet.stellar.org" },
        { name = "SOROBAN_CONTRACT_ID", value = var.testnet_soroban_contract_id },
        { name = "DEBUG_MODE", value = "true" },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
        { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.testnet_database_url[0].arn
        },
        {
          name      = "JWT_SECRET"
          valueFrom = aws_secretsmanager_secret.testnet_jwt_secret[0].arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.testnet_worker[0].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "worker"
        }
      }
    }
  ])
}

# Testnet Server ECS Service
resource "aws_ecs_service" "testnet_server" {
  count = var.testnet_enabled ? 1 : 0

  name            = "${local.name_prefix}-server-testnet"
  cluster         = aws_ecs_cluster.testnet[0].id
  task_definition = aws_ecs_task_definition.testnet_server[0].arn
  desired_count   = var.testnet_server_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.testnet_private[*].id
    security_groups  = [aws_security_group.testnet_ecs_tasks[0].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.testnet_server[0].arn
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

  depends_on = [aws_lb_listener.testnet_http]
}

# Testnet Worker ECS Service
resource "aws_ecs_service" "testnet_worker" {
  count = var.testnet_enabled ? 1 : 0

  name            = "${local.name_prefix}-worker-testnet"
  cluster         = aws_ecs_cluster.testnet[0].id
  task_definition = aws_ecs_task_definition.testnet_worker[0].arn
  desired_count   = var.testnet_worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.testnet_private[*].id
    security_groups  = [aws_security_group.testnet_ecs_tasks[0].id]
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
