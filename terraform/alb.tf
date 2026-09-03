resource "aws_lb" "main" {
  name                       = "${local.name_prefix}-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb"
    enabled = true
  }

  tags = {
    Name = "${local.name_prefix}-alb"
  }
}

resource "aws_lb_target_group" "server" {
  name        = "${local.name_prefix}-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  # Readiness, not liveness. /readyz answers 200 only when Postgres AND Redis
  # both answer (impala-bridge/src/handlers/health.rs, empty body). /health
  # keeps answering 200 with a JSON body whose status merely reads
  # "degraded" — impalactl and openapi.yaml depend on that shape, so it must
  # never be a probe target: keyed on it, every target stayed "healthy"
  # through a full Redis outage while every request was refused (auth is
  # fail-closed on Redis).
  #
  # Thresholds: 8 x 30 s = 4 min of sustained dependency failure before a
  # target is pulled — longer than a Multi-AZ RDS / ElastiCache failover
  # (1-2 min), so a failover does not cascade into ECS replacing every task,
  # while a task that genuinely cannot reach its dependencies is drained in
  # minutes instead of never. healthy_threshold 2 admits a recovered target
  # after 60 s of green.
  #
  # Honest target health also feeds the Route 53 alias records'
  # evaluate_target_health (route53.tf): a long primary dependency outage
  # now fails DNS over to DR instead of pinning clients to a region that
  # refuses every request. Deliberate.
  health_check {
    path                = "/readyz"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 8
    interval            = 30
    timeout             = 5
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = {
    Name = "${local.name_prefix}-tg"
  }
}

# HTTP listener — forwards to target group when no HTTPS cert is configured,
# otherwise redirects to HTTPS (301).
#
# WARNING: the certificate-less forward serves the bridge — logins, JWTs,
# custodial signing — over PLAIN HTTP from 0.0.0.0/0. That is tolerated ONLY
# for explicitly non-production use (the default primary stack targets
# Stellar testnet). It is refused where real money is at stake: variable
# validations reject environment = "production" without certificate_arn, and
# reject live_enabled / any pubnet ecs-stack without a certificate (see
# variables.tf and modules/ecs-stack/variables.tf).
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  dynamic "default_action" {
    for_each = var.certificate_arn != "" ? [1] : []
    content {
      type = "redirect"

      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = var.certificate_arn == "" ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.server.arn
    }
  }
}

# HTTPS listener (optional, only created if certificate_arn is provided)
resource "aws_lb_listener" "https" {
  count = var.certificate_arn != "" ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server.arn
  }
}
