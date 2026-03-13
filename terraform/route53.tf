# =============================================================================
# Route 53 Failover DNS (conditional on domain_name and dr_enabled)
# =============================================================================

# --- Health Check for Primary ALB ---

resource "aws_route53_health_check" "primary" {
  count = var.domain_name != "" ? 1 : 0

  fqdn              = aws_lb.main.dns_name
  port               = 80
  type               = "HTTP"
  resource_path      = "/health"
  failure_threshold  = 3
  request_interval   = 30
  measure_latency    = true

  tags = {
    Name = "${local.name_prefix}-primary-health"
  }
}

# --- Health Check for DR ALB ---

resource "aws_route53_health_check" "dr" {
  count = var.dr_enabled && var.domain_name != "" ? 1 : 0

  fqdn              = aws_lb.dr[0].dns_name
  port               = 80
  type               = "HTTP"
  resource_path      = "/health"
  failure_threshold  = 3
  request_interval   = 30
  measure_latency    = true

  tags = {
    Name = "${local.name_prefix}-dr-health"
  }
}

# --- Failover DNS Records ---

resource "aws_route53_record" "primary" {
  count = var.domain_name != "" && var.route53_zone_id != "" ? 1 : 0

  zone_id = var.route53_zone_id
  name    = "api.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }

  set_identifier = "primary"

  failover_routing_policy {
    type = "PRIMARY"
  }

  health_check_id = aws_route53_health_check.primary[0].id
}

resource "aws_route53_record" "dr" {
  count = var.dr_enabled && var.domain_name != "" && var.route53_zone_id != "" ? 1 : 0

  zone_id = var.route53_zone_id
  name    = "api.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.dr[0].dns_name
    zone_id                = aws_lb.dr[0].zone_id
    evaluate_target_health = true
  }

  set_identifier = "dr"

  failover_routing_policy {
    type = "SECONDARY"
  }

  health_check_id = aws_route53_health_check.dr[0].id
}
