output "alb_dns_name" {
  description = "Stack ALB DNS name"
  value       = aws_lb.this[0].dns_name
}

output "rds_endpoint" {
  description = "Stack RDS endpoint"
  value       = aws_db_instance.this[0].endpoint
}

output "redis_endpoint" {
  description = "Stack Redis primary endpoint"
  value       = aws_elasticache_replication_group.this[0].primary_endpoint_address
}

output "ecs_cluster_name" {
  description = "Stack ECS cluster name"
  value       = aws_ecs_cluster.this[0].name
}

output "ecs_task_role_name" {
  description = "Stack ECS task role name (for attaching extra policies, e.g. the seed-KMS grant in seeds.tf)"
  value       = aws_iam_role.ecs_task[0].name
}
