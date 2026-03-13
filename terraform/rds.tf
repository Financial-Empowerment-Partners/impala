# --- Secrets Manager: RDS password ---

resource "aws_secretsmanager_secret" "rds_password" {
  name        = "${local.name_prefix}-rds-password"
  description = "RDS master password for impala-bridge"
}

resource "aws_secretsmanager_secret_version" "rds_password" {
  secret_id     = aws_secretsmanager_secret.rds_password.id
  secret_string = random_password.rds_password.result
}

# --- Secrets Manager: DATABASE_URL (constructed from RDS endpoint) ---

resource "aws_secretsmanager_secret" "database_url" {
  name        = "${local.name_prefix}-database-url"
  description = "Full DATABASE_URL for impala-bridge"
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = "postgresql://impala_admin:${random_password.rds_password.result}@${aws_db_instance.main.endpoint}/impala"
}

# --- Secrets Manager: JWT secret ---

resource "aws_secretsmanager_secret" "jwt_secret" {
  name        = "${local.name_prefix}-jwt-secret"
  description = "JWT signing secret for impala-bridge"
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = var.jwt_secret
}

# --- KMS Key for RDS encryption ---

resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-rds-kms"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# --- RDS Subnet Group ---

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${local.name_prefix}-db-subnet"
  }
}

# --- RDS PostgreSQL Instance (Multi-AZ, encrypted, automated backups) ---

resource "aws_db_instance" "main" {
  identifier     = "${local.name_prefix}-db"
  engine         = "postgres"
  engine_version = var.rds_engine_version
  instance_class = var.rds_instance_class

  allocated_storage = var.rds_allocated_storage
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  db_name  = "impala"
  username = "impala_admin"
  password = random_password.rds_password.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # Multi-AZ for automatic failover
  multi_az = true

  # Automated backups
  backup_retention_period = var.rds_backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  # Performance monitoring
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn

  publicly_accessible       = false
  skip_final_snapshot       = var.rds_skip_final_snapshot
  final_snapshot_identifier = "${local.name_prefix}-db-final"
  copy_tags_to_snapshot     = true

  # Deletion protection for production
  deletion_protection = var.environment == "production"

  apply_immediately = true

  tags = {
    Name = "${local.name_prefix}-db"
  }
}

# --- Cross-Region Read Replica (conditional on dr_enabled) ---

resource "aws_kms_key" "rds_dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  description             = "KMS key for DR RDS encryption - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "${local.name_prefix}-rds-kms-dr"
  }
}

resource "aws_db_subnet_group" "dr" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  name       = "${local.name_prefix}-db-subnet-dr"
  subnet_ids = aws_subnet.dr_private[*].id

  tags = {
    Name = "${local.name_prefix}-db-subnet-dr"
  }
}

resource "aws_db_instance" "read_replica" {
  count    = var.dr_enabled ? 1 : 0
  provider = aws.dr

  identifier          = "${local.name_prefix}-db-replica"
  replicate_source_db = aws_db_instance.main.arn
  instance_class      = var.rds_instance_class

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_dr[0].arn

  db_subnet_group_name   = aws_db_subnet_group.dr[0].name
  vpc_security_group_ids = [aws_security_group.dr_rds[0].id]

  multi_az            = false
  publicly_accessible = false
  skip_final_snapshot = true

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds_dr[0].arn

  apply_immediately = true

  tags = {
    Name = "${local.name_prefix}-db-replica"
    Role = "read-replica"
  }
}
