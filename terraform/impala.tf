# =============================================================================
# Impala cluster — minimal Fargate stack for impala-api and impala-admin.
# Public-subnet-only networking (no NAT); two separate public ALBs (one per
# service); single task per service; pulls images from the ECR repos defined
# in ecr.tf (aws_ecr_repository.deploy["impala-api"|"impala-admin"]).
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
  description = "Allow public HTTP to ${each.key} ALB"
  vpc_id      = aws_vpc.impala[0].id

  ingress {
    description = "HTTP from world"
    from_port   = 80
    to_port     = 80
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
  description = "Allow container traffic from ${each.key} ALB"
  vpc_id      = aws_vpc.impala[0].id

  ingress {
    description     = "From ${each.key} ALB"
    from_port       = each.value.container_port
    to_port         = each.value.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.impala_alb[each.key].id]
  }

  egress {
    description = "All egress (ECR pull, AWS APIs)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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

resource "aws_lb_listener" "impala_http" {
  for_each          = var.impala_enabled ? local.impala_services : {}
  load_balancer_arn = aws_lb.impala[each.key].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.impala[each.key].arn
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

  container_definitions = jsonencode([{
    name      = each.key
    image     = "${aws_ecr_repository.deploy[each.key].repository_url}:${var.container_image_tag}"
    essential = true

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

  depends_on = [aws_lb_listener.impala_http]
}
