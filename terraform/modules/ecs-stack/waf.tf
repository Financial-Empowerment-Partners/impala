# =============================================================================
# WAFv2 web ACL on the stack ALB (var.waf_enabled — deliberately default-ON,
# the one WS4 knob that breaks the "defaults preserve pre-change behavior"
# module convention; SECURITY.md's WAF claim becomes true with this file).
#
# AWS managed rule groups (Common / KnownBadInputs / SQLi, priorities
# 10/20/30, override_action none so each group's own block actions stand)
# plus a per-IP rate-based block rule at priority 40. Known false-positive
# surface: CommonRuleSet's SizeRestrictions_BODY blocks request bodies > 8 KB
# — the bridge's real payloads are far smaller (its own cap is 1 MB), but if
# legitimate traffic ever trips a managed rule, add a rule_action_override
# on that rule here or set waf_enabled = false per stack.
# =============================================================================

resource "aws_wafv2_web_acl" "this" {
  count = var.waf_enabled ? 1 : 0

  name        = "${var.name_prefix}-waf-${var.env}"
  description = "Managed Common/KnownBadInputs/SQLi rule groups + per-IP rate limit for the ${var.env} ALB"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Core ruleset: broad exploit categories (XSS, LFI, protocol abuse, ...).
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-${var.env}-waf-common"
      sampled_requests_enabled   = true
    }
  }

  # Request patterns known to be invalid or malicious (log4j-style probes,
  # malformed hosts, ...).
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-${var.env}-waf-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # SQL-injection signatures — defense in depth in front of the bridge's
  # parameterized sqlx queries.
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-${var.env}-waf-sqli"
      sampled_requests_enabled   = true
    }
  }

  # Per-IP flood control at the edge, complementing the bridge's Redis-backed
  # per-account rate limiting (which only applies after authentication).
  rule {
    name     = "rate-limit"
    priority = 40

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name_prefix}-${var.env}-waf-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-waf-${var.env}"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "${var.name_prefix}-waf-${var.env}"
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  count = var.waf_enabled ? 1 : 0

  resource_arn = aws_lb.this[0].arn
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}
