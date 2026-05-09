output "ecr_repository_url" {
  description = "ECR repository URL for docker push"
  value       = aws_ecr_repository.bridge.repository_url
}

# --- Testnet outputs (conditional) ---

output "testnet_alb_dns_name" {
  description = "Testnet ALB DNS name"
  value       = var.testnet_enabled ? aws_lb.testnet[0].dns_name : "Testnet not enabled"
}

output "testnet_rds_endpoint" {
  description = "Testnet RDS endpoint"
  value       = var.testnet_enabled ? aws_db_instance.testnet[0].endpoint : "Testnet not enabled"
}

output "testnet_redis_endpoint" {
  description = "Testnet Redis endpoint"
  value       = var.testnet_enabled ? aws_elasticache_replication_group.testnet[0].primary_endpoint_address : "Testnet not enabled"
}

output "testnet_ecs_cluster_name" {
  description = "Testnet ECS cluster name"
  value       = var.testnet_enabled ? aws_ecs_cluster.testnet[0].name : "Testnet not enabled"
}

# --- Live outputs (conditional) ---

output "live_alb_dns_name" {
  description = "Live ALB DNS name"
  value       = var.live_enabled ? aws_lb.live[0].dns_name : "Live not enabled"
}

output "live_rds_endpoint" {
  description = "Live RDS endpoint"
  value       = var.live_enabled ? aws_db_instance.live[0].endpoint : "Live not enabled"
}

output "live_redis_endpoint" {
  description = "Live Redis endpoint"
  value       = var.live_enabled ? aws_elasticache_replication_group.live[0].primary_endpoint_address : "Live not enabled"
}

output "live_ecs_cluster_name" {
  description = "Live ECS cluster name"
  value       = var.live_enabled ? aws_ecs_cluster.live[0].name : "Live not enabled"
}

# --- Impala cluster outputs (conditional) ---

output "impala_ecs_cluster_name" {
  description = "Impala ECS cluster name"
  value       = var.impala_enabled ? aws_ecs_cluster.impala[0].name : "Impala not enabled"
}

output "impala_api_alb_dns_name" {
  description = "Impala-api ALB DNS name"
  value       = var.impala_enabled ? aws_lb.impala["impala-api"].dns_name : "Impala not enabled"
}

output "impala_admin_alb_dns_name" {
  description = "Impala-admin ALB DNS name"
  value       = var.impala_enabled ? aws_lb.impala["impala-admin"].dns_name : "Impala not enabled"
}
