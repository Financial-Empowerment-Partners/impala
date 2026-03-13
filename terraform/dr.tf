# =============================================================================
# Disaster Recovery Region Infrastructure
# All resources conditional on var.dr_enabled
# =============================================================================

# --- DR Availability Zones ---

data "aws_availability_zones" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr
  state    = "available"
}

# =============================================================================
# DR VPC + Networking
# =============================================================================

resource "aws_vpc" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  cidr_block           = var.dr_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-vpc-dr"
  }
}

resource "aws_subnet" "dr_public" {
  count    = var.dr_enabled ? var.az_count : 0
  provider = aws.dr

  vpc_id            = aws_vpc.dr[0].id
  cidr_block        = cidrsubnet(var.dr_vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.dr[0].names[count.index]

  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-dr-public-${count.index}"
  }
}

resource "aws_subnet" "dr_private" {
  count    = var.dr_enabled ? var.az_count : 0
  provider = aws.dr

  vpc_id            = aws_vpc.dr[0].id
  cidr_block        = cidrsubnet(var.dr_vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.dr[0].names[count.index]

  tags = {
    Name = "${local.name_prefix}-dr-private-${count.index}"
  }
}

resource "aws_internet_gateway" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  vpc_id = aws_vpc.dr[0].id

  tags = {
    Name = "${local.name_prefix}-igw-dr"
  }
}

resource "aws_eip" "dr_nat" {
  count    = var.dr_enabled ? var.az_count : 0
  provider = aws.dr

  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-dr-nat-eip-${count.index}"
  }
}

resource "aws_nat_gateway" "dr" {
  count    = var.dr_enabled ? var.az_count : 0
  provider = aws.dr

  allocation_id = aws_eip.dr_nat[count.index].id
  subnet_id     = aws_subnet.dr_public[count.index].id

  tags = {
    Name = "${local.name_prefix}-dr-nat-${count.index}"
  }

  depends_on = [aws_internet_gateway.dr]
}

resource "aws_route_table" "dr_public" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  vpc_id = aws_vpc.dr[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.dr[0].id
  }

  tags = {
    Name = "${local.name_prefix}-dr-public-rt"
  }
}

resource "aws_route_table_association" "dr_public" {
  count    = var.dr_enabled ? var.az_count : 0
  provider = aws.dr

  subnet_id      = aws_subnet.dr_public[count.index].id
  route_table_id = aws_route_table.dr_public[0].id
}

resource "aws_route_table" "dr_private" {
  count    = var.dr_enabled ? var.az_count : 0
  provider = aws.dr

  vpc_id = aws_vpc.dr[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.dr[count.index].id
  }

  tags = {
    Name = "${local.name_prefix}-dr-private-rt-${count.index}"
  }
}

resource "aws_route_table_association" "dr_private" {
  count    = var.dr_enabled ? var.az_count : 0
  provider = aws.dr

  subnet_id      = aws_subnet.dr_private[count.index].id
  route_table_id = aws_route_table.dr_private[count.index].id
}

# =============================================================================
# DR Security Groups
# =============================================================================

resource "aws_security_group" "dr_alb" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name_prefix = "${local.name_prefix}-dr-alb-"
  description = "Allow HTTP/HTTPS inbound to DR ALB"
  vpc_id      = aws_vpc.dr[0].id

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
    Name = "${local.name_prefix}-dr-alb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "dr_ecs_tasks" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name_prefix = "${local.name_prefix}-dr-ecs-"
  description = "Allow inbound from DR ALB, outbound all"
  vpc_id      = aws_vpc.dr[0].id

  ingress {
    description     = "From DR ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.dr_alb[0].id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-dr-ecs-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "dr_rds" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name_prefix = "${local.name_prefix}-dr-rds-"
  description = "Allow PostgreSQL from DR ECS tasks"
  vpc_id      = aws_vpc.dr[0].id

  ingress {
    description     = "PostgreSQL from DR ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.dr_ecs_tasks[0].id]
  }

  tags = {
    Name = "${local.name_prefix}-dr-rds-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "dr_redis" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name_prefix = "${local.name_prefix}-dr-redis-"
  description = "Allow Redis from DR ECS tasks"
  vpc_id      = aws_vpc.dr[0].id

  ingress {
    description     = "Redis from DR ECS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.dr_ecs_tasks[0].id]
  }

  tags = {
    Name = "${local.name_prefix}-dr-redis-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# DR ALB
# =============================================================================

resource "aws_lb" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name               = "${local.name_prefix}-alb-dr"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.dr_alb[0].id]
  subnets            = aws_subnet.dr_public[*].id

  tags = {
    Name = "${local.name_prefix}-alb-dr"
  }
}

resource "aws_lb_target_group" "dr_server" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name        = "${local.name_prefix}-tg-dr"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.dr[0].id
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
    Name = "${local.name_prefix}-tg-dr"
  }
}

resource "aws_lb_listener" "dr_http" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  load_balancer_arn = aws_lb.dr[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.dr_server[0].arn
  }
}

# =============================================================================
# DR ElastiCache
# =============================================================================

resource "aws_elasticache_subnet_group" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name       = "${local.name_prefix}-redis-subnet-dr"
  subnet_ids = aws_subnet.dr_private[*].id

  tags = {
    Name = "${local.name_prefix}-redis-subnet-dr"
  }
}

resource "aws_elasticache_replication_group" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  replication_group_id = "${local.name_prefix}-redis-dr"
  description          = "DR Redis replication group for ${local.name_prefix}"

  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.redis_node_type
  num_cache_clusters   = var.az_count
  port                 = 6379
  parameter_group_name = "default.redis7"

  subnet_group_name  = aws_elasticache_subnet_group.dr[0].name
  security_group_ids = [aws_security_group.dr_redis[0].id]

  automatic_failover_enabled = true
  multi_az_enabled           = true

  at_rest_encryption_enabled = true
  transit_encryption_enabled = false

  tags = {
    Name = "${local.name_prefix}-redis-dr"
  }
}

# =============================================================================
# DR SNS/SQS (Worker Queue)
# =============================================================================

resource "aws_sns_topic" "dr_jobs" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name = "${local.name_prefix}-jobs-dr"

  tags = {
    Name = "${local.name_prefix}-jobs-dr"
  }
}

resource "aws_sqs_queue" "dr_worker_dlq" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name                      = "${local.name_prefix}-worker-dlq-dr"
  message_retention_seconds = 1209600

  tags = {
    Name = "${local.name_prefix}-worker-dlq-dr"
  }
}

resource "aws_sqs_queue" "dr_worker" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name                       = "${local.name_prefix}-worker-dr"
  visibility_timeout_seconds = var.sqs_visibility_timeout_seconds
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dr_worker_dlq[0].arn
    maxReceiveCount     = var.sqs_max_receive_count
  })

  tags = {
    Name = "${local.name_prefix}-worker-dr"
  }
}

resource "aws_sns_topic_subscription" "dr_worker" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  topic_arn = aws_sns_topic.dr_jobs[0].arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.dr_worker[0].arn
}

resource "aws_sqs_queue_policy" "dr_worker" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  queue_url = aws_sqs_queue.dr_worker[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSNSSend"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.dr_worker[0].arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.dr_jobs[0].arn
          }
        }
      }
    ]
  })
}

# =============================================================================
# DR Secrets Manager
# =============================================================================

resource "aws_secretsmanager_secret" "dr_database_url" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name        = "${local.name_prefix}-database-url-dr"
  description = "DATABASE_URL for DR impala-bridge (read replica)"
}

resource "aws_secretsmanager_secret_version" "dr_database_url" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  secret_id     = aws_secretsmanager_secret.dr_database_url[0].id
  secret_string = "postgresql://impala_admin:${random_password.rds_password.result}@${aws_db_instance.read_replica[0].endpoint}/impala"
}

resource "aws_secretsmanager_secret" "dr_jwt_secret" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name        = "${local.name_prefix}-jwt-secret-dr"
  description = "JWT signing secret for DR impala-bridge"
}

resource "aws_secretsmanager_secret_version" "dr_jwt_secret" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  secret_id     = aws_secretsmanager_secret.dr_jwt_secret[0].id
  secret_string = var.jwt_secret
}

# =============================================================================
# DR IAM Roles
# =============================================================================

resource "aws_iam_role" "dr_ecs_task_execution" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name = "${local.name_prefix}-ecs-exec-dr"

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

resource "aws_iam_role_policy_attachment" "dr_ecs_task_execution" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  role       = aws_iam_role.dr_ecs_task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "dr_execution_secrets" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name = "${local.name_prefix}-exec-secrets-dr"
  role = aws_iam_role.dr_ecs_task_execution[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = [
          aws_secretsmanager_secret.dr_database_url[0].arn,
          aws_secretsmanager_secret.dr_jwt_secret[0].arn,
        ]
      }
    ]
  })
}

resource "aws_iam_role" "dr_ecs_task" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name = "${local.name_prefix}-ecs-task-dr"

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

resource "aws_iam_role_policy" "dr_ecs_task_sqs" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name = "${local.name_prefix}-task-sqs-dr"
  role = aws_iam_role.dr_ecs_task[0].id

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
        Resource = aws_sqs_queue.dr_worker[0].arn
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.dr_jobs[0].arn
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
# DR CloudWatch Log Groups
# =============================================================================

resource "aws_cloudwatch_log_group" "dr_server" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name              = "/ecs/${local.name_prefix}-server-dr"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "dr_worker" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name              = "/ecs/${local.name_prefix}-worker-dr"
  retention_in_days = 30
}

# =============================================================================
# DR ECS Cluster + Services
# =============================================================================

resource "aws_ecs_cluster" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name = "${local.name_prefix}-cluster-dr"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${local.name_prefix}-cluster-dr"
  }
}

# DR Server Task Definition
resource "aws_ecs_task_definition" "dr_server" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  family                   = "${local.name_prefix}-server-dr"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.server_cpu
  memory                   = var.server_memory
  execution_role_arn       = aws_iam_role.dr_ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.dr_ecs_task[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode([
    {
      name      = "impala-bridge-server"
      image     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.dr_region}.amazonaws.com/${var.project_name}:${var.container_image_tag}"
      essential = true

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "RUN_MODE", value = "server" },
        { name = "SERVICE_ADDRESS", value = "0.0.0.0:8080" },
        { name = "REDIS_URL", value = "redis://${aws_elasticache_replication_group.dr[0].primary_endpoint_address}:6379" },
        { name = "STELLAR_HORIZON_URL", value = var.stellar_horizon_url },
        { name = "STELLAR_RPC_URL", value = var.stellar_rpc_url },
        { name = "SNS_TOPIC_ARN", value = aws_sns_topic.dr_jobs[0].arn },
        { name = "AWS_REGION", value = var.dr_region },
        { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
        { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.dr_database_url[0].arn
        },
        {
          name      = "JWT_SECRET"
          valueFrom = aws_secretsmanager_secret.dr_jwt_secret[0].arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dr_server[0].name
          "awslogs-region"        = var.dr_region
          "awslogs-stream-prefix" = "server"
        }
      }
    }
  ])
}

# DR Worker Task Definition
resource "aws_ecs_task_definition" "dr_worker" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  family                   = "${local.name_prefix}-worker-dr"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.dr_ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.dr_ecs_task[0].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode([
    {
      name      = "impala-bridge-worker"
      image     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.dr_region}.amazonaws.com/${var.project_name}:${var.container_image_tag}"
      essential = true

      environment = [
        { name = "RUN_MODE", value = "worker" },
        { name = "SQS_QUEUE_URL", value = aws_sqs_queue.dr_worker[0].url },
        { name = "REDIS_URL", value = "redis://${aws_elasticache_replication_group.dr[0].primary_endpoint_address}:6379" },
        { name = "STELLAR_HORIZON_URL", value = var.stellar_horizon_url },
        { name = "STELLAR_RPC_URL", value = var.stellar_rpc_url },
        { name = "AWS_REGION", value = var.dr_region },
        { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
        { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.dr_database_url[0].arn
        },
        {
          name      = "JWT_SECRET"
          valueFrom = aws_secretsmanager_secret.dr_jwt_secret[0].arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.dr_worker[0].name
          "awslogs-region"        = var.dr_region
          "awslogs-stream-prefix" = "worker"
        }
      }
    }
  ])
}

# DR Server ECS Service
resource "aws_ecs_service" "dr_server" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name            = "${local.name_prefix}-server-dr"
  cluster         = aws_ecs_cluster.dr[0].id
  task_definition = aws_ecs_task_definition.dr_server[0].arn
  desired_count   = var.dr_server_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.dr_private[*].id
    security_groups  = [aws_security_group.dr_ecs_tasks[0].id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.dr_server[0].arn
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

  depends_on = [aws_lb_listener.dr_http]
}

# DR Worker ECS Service
resource "aws_ecs_service" "dr_worker" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name            = "${local.name_prefix}-worker-dr"
  cluster         = aws_ecs_cluster.dr[0].id
  task_definition = aws_ecs_task_definition.dr_worker[0].arn
  desired_count   = var.dr_worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.dr_private[*].id
    security_groups  = [aws_security_group.dr_ecs_tasks[0].id]
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
