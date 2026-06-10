output "ecr_repository_url" {
  description = "ECR repository URL for docker push"
  value       = aws_ecr_repository.bridge.repository_url
}

# --- Testnet outputs (conditional) ---

output "testnet_alb_dns_name" {
  description = "Testnet ALB DNS name"
  value       = var.testnet_enabled ? module.testnet[0].alb_dns_name : "Testnet not enabled"
}

output "testnet_rds_endpoint" {
  description = "Testnet RDS endpoint"
  value       = var.testnet_enabled ? module.testnet[0].rds_endpoint : "Testnet not enabled"
}

output "testnet_redis_endpoint" {
  description = "Testnet Redis endpoint"
  value       = var.testnet_enabled ? module.testnet[0].redis_endpoint : "Testnet not enabled"
}

output "testnet_ecs_cluster_name" {
  description = "Testnet ECS cluster name"
  value       = var.testnet_enabled ? module.testnet[0].ecs_cluster_name : "Testnet not enabled"
}

# --- Live outputs (conditional) ---

output "live_alb_dns_name" {
  description = "Live ALB DNS name"
  value       = var.live_enabled ? module.live[0].alb_dns_name : "Live not enabled"
}

output "live_rds_endpoint" {
  description = "Live RDS endpoint"
  value       = var.live_enabled ? module.live[0].rds_endpoint : "Live not enabled"
}

output "live_redis_endpoint" {
  description = "Live Redis endpoint"
  value       = var.live_enabled ? module.live[0].redis_endpoint : "Live not enabled"
}

output "live_ecs_cluster_name" {
  description = "Live ECS cluster name"
  value       = var.live_enabled ? module.live[0].ecs_cluster_name : "Live not enabled"
}

# --- Impala cluster outputs (conditional) ---

output "impala_ecs_cluster_name" {
  description = "Impala ECS cluster name"
  value       = var.impala_enabled ? module.impala[0].ecs_cluster_name : "Impala not enabled"
}

output "impala_api_alb_dns_name" {
  description = "Impala-api ALB DNS name"
  value       = var.impala_enabled ? module.impala[0].alb_dns_names["impala-api"] : "Impala not enabled"
}

output "impala_admin_alb_dns_name" {
  description = "Impala-admin ALB DNS name"
  value       = var.impala_enabled ? module.impala[0].alb_dns_names["impala-admin"] : "Impala not enabled"
}
