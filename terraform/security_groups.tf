# --- ALB Security Group ---

resource "aws_security_group" "alb" {
  name_prefix = "${local.name_prefix}-alb-"
  description = "Allow HTTP/HTTPS inbound to ALB"
  vpc_id      = aws_vpc.main.id

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
    Name = "${local.name_prefix}-alb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# --- ECS Tasks Security Group ---

resource "aws_security_group" "ecs_tasks" {
  name_prefix = "${local.name_prefix}-ecs-"
  description = "Allow inbound from ALB, outbound all"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "From ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # HTTPS outbound (Stellar, SNS, SQS, SES, ECR, Secrets Manager)
  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-ecs-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Egress rules defined as standalone resources to avoid circular dependency
# (ECS SG -> RDS SG -> ECS SG and ECS SG -> Redis SG -> ECS SG)

resource "aws_security_group_rule" "ecs_to_rds" {
  type                     = "egress"
  description              = "PostgreSQL to RDS"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ecs_tasks.id
  source_security_group_id = aws_security_group.rds.id
}

resource "aws_security_group_rule" "ecs_to_redis" {
  type                     = "egress"
  description              = "Redis to ElastiCache"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ecs_tasks.id
  source_security_group_id = aws_security_group.redis.id
}

# --- RDS Security Group ---

resource "aws_security_group" "rds" {
  name_prefix = "${local.name_prefix}-rds-"
  description = "Allow PostgreSQL from ECS tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from ECS"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = {
    Name = "${local.name_prefix}-rds-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# --- ElastiCache Security Group ---

resource "aws_security_group" "redis" {
  name_prefix = "${local.name_prefix}-redis-"
  description = "Allow Redis from ECS tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from ECS"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = {
    Name = "${local.name_prefix}-redis-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}
