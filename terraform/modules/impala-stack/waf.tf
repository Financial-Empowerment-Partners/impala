# =============================================================================
# WAFv2 web ACL for both service ALBs (var.waf_enabled — deliberately
# default-ON, the one WS4 knob that breaks the zero-diff module convention).
#
# One SHARED web ACL: impala-api and impala-admin are placeholder services
# with identical exposure, so per-service ACLs would double the fixed cost
# for no policy difference. Same rule set as modules/ecs-stack/waf.tf: AWS
# managed Common / KnownBadInputs / SQLi groups (priorities 10/20/30,
# override_action none) + per-IP rate-based block rule at priority 40.
# CommonRuleSet's SizeRestrictions_BODY blocks request bodies > 8 KB — add a
# rule_action_override or set waf_enabled = false if legitimate traffic ever
# trips a managed rule.
# =============================================================================

resource "aws_wafv2_web_acl" "this" {
  count = var.waf_enabled ? 1 : 0

  name        = "impala-waf"
  description = "Managed Common/KnownBadInputs/SQLi rule groups + per-IP rate limit, shared by the impala-api and impala-admin ALBs"
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
      metric_name                = "impala-waf-common"
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
      metric_name                = "impala-waf-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # SQL-injection signatures.
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
      metric_name                = "impala-waf-sqli"
      sampled_requests_enabled   = true
    }
  }

  # Per-IP flood control at the edge.
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
      metric_name                = "impala-waf-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "impala-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "impala-waf"
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  for_each = var.waf_enabled ? local.services : {}

  resource_arn = aws_lb.this[each.key].arn
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}
