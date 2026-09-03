locals {
  # STELLAR_NETWORK_PASSPHRASE for the primary + DR bridge. The bridge derives
  # this from STELLAR_NETWORK when the variable is absent (config.rs), so it
  # is injected only to make the deployed task definition state which network
  # it signs for — the same pair the live stack passes in live.tf.
  stellar_network_passphrase = {
    testnet = "Test SDF Network ; September 2015"
    pubnet  = "Public Global Stellar Network ; September 2015"
  }[var.stellar_network]

  # Browser-facing settings for the primary + DR SERVER tasks only (the CORS
  # gate runs in server mode; the worker serves no HTTP). Omitted, not "",
  # when unset so a testnet primary stack keeps its current env list;
  # variables.tf requires cors_allowed_origins when stellar_network is pubnet.
  primary_web_env = concat(
    var.cors_allowed_origins != null ? [{ name = "CORS_ALLOWED_ORIGINS", value = var.cors_allowed_origins }] : [],
    var.public_endpoint != null ? [{ name = "PUBLIC_ENDPOINT", value = var.public_endpoint }] : [],
  )
}

# --- ECS Cluster ---

resource "aws_ecs_cluster" "main" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${local.name_prefix}-cluster"
  }
}

# --- CloudWatch Log Groups ---

resource "aws_cloudwatch_log_group" "server" {
  name              = "/ecs/${local.name_prefix}-server"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${local.name_prefix}-worker"
  retention_in_days = 30
}

# --- Server Task Definition ---

resource "aws_ecs_task_definition" "server" {
  family                   = "${local.name_prefix}-server"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.server_cpu
  memory                   = var.server_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode(concat(
    [
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

        # STELLAR_NETWORK selects the passphrase the bridge signs with; without
        # it the bridge runs in testnet mode whatever the Horizon URL says.
        # CORS_ALLOWED_ORIGINS / PUBLIC_ENDPOINT (local.primary_web_env) and
        # the operator extras (var.bridge_extra_environment) are appended
        # last; both are empty by default.
        environment = concat(
          [
            { name = "RUN_MODE", value = "server" },
            { name = "SERVICE_ADDRESS", value = "0.0.0.0:8080" },
            { name = "REDIS_URL", value = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379" },
            { name = "STELLAR_NETWORK", value = var.stellar_network },
            { name = "STELLAR_HORIZON_URL", value = var.stellar_horizon_url },
            { name = "STELLAR_RPC_URL", value = var.stellar_rpc_url },
            { name = "STELLAR_NETWORK_PASSPHRASE", value = local.stellar_network_passphrase },
            { name = "SNS_TOPIC_ARN", value = aws_sns_topic.jobs.arn },
            { name = "AWS_REGION", value = var.aws_region },
            { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
            { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
          ],
          local.otel_app_env,
          local.seed_protection_env,
          local.primary_web_env,
          var.bridge_extra_environment,
        )

        secrets = [
          {
            name      = "DATABASE_URL"
            valueFrom = aws_secretsmanager_secret.database_url.arn
          },
          {
            name      = "JWT_SECRET"
            valueFrom = aws_secretsmanager_secret.jwt_secret.arn
          },
        ]

        logConfiguration = {
          logDriver = "awslogs"
          options = {
            "awslogs-group"         = aws_cloudwatch_log_group.server.name
            "awslogs-region"        = var.aws_region
            "awslogs-stream-prefix" = "server"
          }
        }
      }
    ],
    local.otel_sidecar_container,
  ))
}

# --- Worker Task Definition ---

resource "aws_ecs_task_definition" "worker" {
  family                   = "${local.name_prefix}-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode(concat(
    [
      {
        name      = "impala-bridge-worker"
        image     = "${aws_ecr_repository.bridge.repository_url}:${var.container_image_tag}"
        essential = true

        readonlyRootFilesystem = true
        user                   = "1000:1000"

        # The worker signs transactions too, so it needs STELLAR_NETWORK (+
        # passphrase) exactly like the server. CORS/PUBLIC_ENDPOINT are
        # server-only; the operator extras are appended last.
        environment = concat(
          [
            { name = "RUN_MODE", value = "worker" },
            { name = "SQS_QUEUE_URL", value = aws_sqs_queue.worker.url },
            { name = "REDIS_URL", value = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379" },
            { name = "STELLAR_NETWORK", value = var.stellar_network },
            { name = "STELLAR_HORIZON_URL", value = var.stellar_horizon_url },
            { name = "STELLAR_RPC_URL", value = var.stellar_rpc_url },
            { name = "STELLAR_NETWORK_PASSPHRASE", value = local.stellar_network_passphrase },
            { name = "AWS_REGION", value = var.aws_region },
            { name = "SES_FROM_ADDRESS", value = var.ses_from_address },
            { name = "FCM_PROJECT_ID", value = var.fcm_project_id },
          ],
          local.otel_app_env,
          local.seed_protection_env,
          var.bridge_extra_environment,
        )

        secrets = [
          {
            name      = "DATABASE_URL"
            valueFrom = aws_secretsmanager_secret.database_url.arn
          },
          {
            name      = "JWT_SECRET"
            valueFrom = aws_secretsmanager_secret.jwt_secret.arn
          },
        ]

        logConfiguration = {
          logDriver = "awslogs"
          options = {
            "awslogs-group"         = aws_cloudwatch_log_group.worker.name
            "awslogs-region"        = var.aws_region
            "awslogs-stream-prefix" = "worker"
          }
        }
      }
    ],
    local.otel_sidecar_container,
  ))
}

# --- Server ECS Service ---

resource "aws_ecs_service" "server" {
  name            = "${local.name_prefix}-server"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.server.arn
  desired_count   = var.server_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.server.arn
    container_name   = "impala-bridge-server"
    container_port   = 8080
  }

  # A fresh task gets 120 s to open its DB/Redis pools before ECS acts on
  # ALB health (the /readyz check in alb.tf is a real dependency check).
  # Only valid on services with a load_balancer block — never on the worker.
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

# --- Worker ECS Service ---

resource "aws_ecs_service" "worker" {
  name            = "${local.name_prefix}-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs_tasks.id]
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

# --- One-off DB migration task definition ---
# No service: invoked manually via `aws ecs run-task` with RUN_MODE=migrate
# (applies ./migrations then exits). See docs/runbooks/deploy.md and the
# `migrate_task_definition` / `migrate_network_config` outputs.

resource "aws_ecs_task_definition" "migrate" {
  family                   = "${local.name_prefix}-migrate"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.server_cpu
  memory                   = var.server_memory
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.container_architecture
  }

  container_definitions = jsonencode([
    {
      name      = "impala-bridge-migrate"
      image     = "${aws_ecr_repository.bridge.repository_url}:${var.container_image_tag}"
      essential = true

      readonlyRootFilesystem = true
      user                   = "1000:1000"

      environment = [
        { name = "RUN_MODE", value = "migrate" },
        { name = "AWS_REGION", value = var.aws_region },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.database_url.arn
        },
        {
          name      = "JWT_SECRET"
          valueFrom = aws_secretsmanager_secret.jwt_secret.arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.server.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "migrate"
        }
      }
    }
  ])
}
