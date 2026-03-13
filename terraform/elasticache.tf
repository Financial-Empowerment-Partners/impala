resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name_prefix}-redis-subnet"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${local.name_prefix}-redis-subnet"
  }
}

# Multi-AZ Redis replication group with automatic failover
resource "aws_elasticache_replication_group" "main" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "Redis replication group for ${local.name_prefix}"

  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.redis_node_type
  num_cache_clusters   = var.az_count
  port                 = 6379
  parameter_group_name = "default.redis7"

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  automatic_failover_enabled = true
  multi_az_enabled           = true

  at_rest_encryption_enabled = true
  transit_encryption_enabled = false # Would require app-level TLS config changes

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}
