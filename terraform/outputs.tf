output "alb_dns_name" {
  description = "Public DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "ecr_repository_url" {
  description = "ECR repository URL for docker push"
  value       = aws_ecr_repository.bridge.repository_url
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.main.endpoint
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "sqs_queue_url" {
  description = "SQS worker queue URL"
  value       = aws_sqs_queue.worker.url
}

output "sqs_dlq_url" {
  description = "SQS dead-letter queue URL"
  value       = aws_sqs_queue.worker_dlq.url
}

output "sns_topic_arn" {
  description = "SNS job dispatch topic ARN"
  value       = aws_sns_topic.jobs.arn
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "server_log_group" {
  description = "CloudWatch log group for server tasks"
  value       = aws_cloudwatch_log_group.server.name
}

output "worker_log_group" {
  description = "CloudWatch log group for worker tasks"
  value       = aws_cloudwatch_log_group.worker.name
}

output "cloudwatch_dashboard_url" {
  description = "URL to the CloudWatch monitoring dashboard"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "alerts_topic_arn" {
  description = "SNS topic ARN for monitoring alerts (if configured)"
  value       = var.alert_email != "" ? aws_sns_topic.alerts[0].arn : "not configured - set alert_email variable"
}

output "s3_backup_bucket" {
  description = "S3 bucket for backups"
  value       = aws_s3_bucket.backups.id
}

# --- DR Outputs (conditional) ---

output "dr_alb_dns_name" {
  description = "DR region ALB DNS name"
  value       = var.dr_enabled ? aws_lb.dr[0].dns_name : "DR not enabled"
}

output "dr_rds_replica_endpoint" {
  description = "DR region RDS read replica endpoint"
  value       = var.dr_enabled ? aws_db_instance.read_replica[0].endpoint : "DR not enabled"
}

output "dr_redis_endpoint" {
  description = "DR region ElastiCache Redis endpoint"
  value       = var.dr_enabled ? aws_elasticache_replication_group.dr[0].primary_endpoint_address : "DR not enabled"
}

output "dr_ecs_cluster_name" {
  description = "DR region ECS cluster name"
  value       = var.dr_enabled ? aws_ecs_cluster.dr[0].name : "DR not enabled"
}

output "failover_dns" {
  description = "Route 53 failover DNS record"
  value       = var.domain_name != "" && var.route53_zone_id != "" ? "api.${var.domain_name}" : "not configured - set domain_name and route53_zone_id"
}
