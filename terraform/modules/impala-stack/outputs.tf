output "ecs_cluster_name" {
  description = "Impala ECS cluster name"
  value       = aws_ecs_cluster.this.name
}

output "alb_dns_names" {
  description = "Map of service name (impala-api / impala-admin) to ALB DNS name"
  value       = { for k, lb in aws_lb.this : k => lb.dns_name }
}
