# WAF Web ACL - Cloudflare Only Access
resource "aws_wafv2_web_acl" "main" {
  name  = var.waf_name[local.workspace]
  scope = var.waf_scope

  default_action {
    block {}  # Changed to block by default
  }

  # Rule 1: ONLY Allow Cloudflare IPs - Block everything else
  rule {
    name     = "Allow-Only-Cloudflare-IPs"
    priority = 1

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.cloudflare_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "Allow-Only-Cloudflare-IPs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Rate Limiting Rule - Applies to ALL traffic (including Cloudflare)
  rule {
    name     = "RateLimitRule"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000  # requests per 5-minute window
        aggregate_key_type = "IP"
        # Removed scope_down_statement - applies to ALL IPs now
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: Geographic Restriction Rule - Applies to ALL traffic (including Cloudflare)
  rule {
    name     = "GeoRestrictionRule"
    priority = 3

    action {
      block {}
    }

    statement {
      geo_match_statement {
        # Block these countries - applies to ALL traffic now
        country_codes = [
          "CN", # China
          "RU", # Russia
          "KP", # North Korea
          "IR", # Iran
          "CU", # Cuba
          "SY", # Syria
          "IQ", # Iraq
          "AF"  # Afghanistan
        ]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "GeoRestrictionRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Malicious Pattern Detection Rule - Applies to ALL traffic
  rule {
    name     = "MaliciousPatternRule"
    priority = 4

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.malicious_patterns.arn
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority = 3
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.malicious_patterns.arn
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority = 3
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.malicious_patterns.arn
            field_to_match {
              body {
                oversize_handling = "CONTINUE"
              }
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
            text_transformation {
              priority = 3
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "MaliciousPatternRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Amazon IP Reputation List - Applies to ALL traffic
  rule {
    name     = "AmazonIPReputationList"
    priority = 5

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AmazonIPReputationList"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: Anonymous IP List - Applies to ALL traffic
  rule {
    name     = "AnonymousIPList"
    priority = 6

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AnonymousIPList"
      sampled_requests_enabled   = true
    }
  }

  # Rule 7: Core Rule Set - Applies to ALL traffic
  rule {
    name     = "CoreRuleSet"
    priority = 7
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
        
        rule_action_override {
          name = "SizeRestrictions_QUERYSTRING"
          action_to_use {
            count {}
          }
        }
        
        rule_action_override {
          name = "NoUserAgent_HEADER"
          action_to_use {
            count {}
          }
        }
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CoreRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 8: Known Bad Inputs - Applies to ALL traffic
  rule {
    name     = "KnownBadInputs"
    priority = 8

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
      metric_name                = "KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 9: Bot Control - Applies to ALL traffic
  rule {
    name     = "BotControl"
    priority = 9

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BotControl"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.waf_name[local.workspace]
    sampled_requests_enabled   = true
  }

  tags = {
    Name        = var.waf_name[local.workspace]
    Environment = local.workspace
  }
}

# Create CloudFlare IP set (same as before)
resource "aws_wafv2_ip_set" "cloudflare_ips" {
  name               = "AllowFromCF"
  description        = "Cloudflare IP addresses"
  scope              = var.waf_scope
  ip_address_version = "IPV4"

  # Cloudflare IPv4 ranges - update these as needed
  addresses = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
  ]

  tags = {
    Name        = "AllowFromCF"
    Environment = local.workspace
  }
}

# Create Regex Pattern Set for malicious patterns (same as before)
resource "aws_wafv2_regex_pattern_set" "malicious_patterns" {
  name  = "${var.waf_name[local.workspace]}-malicious-patterns"
  scope = var.waf_scope

  regular_expression {
    regex_string = "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table)"
  }

  regular_expression {
    regex_string = "(?i)(<script|javascript:|vbscript:|onload=|onerror=)"
  }

  regular_expression {
    regex_string = "(?i)(\\.\\.[\\/\\\\]|\\.\\.%2f|\\.\\.%5c)"
  }

  regular_expression {
    regex_string = "(?i)(eval\\s*\\(|exec\\s*\\(|system\\s*\\(|passthru\\s*\\()"
  }

  regular_expression {
    regex_string = "(?i)(cmd\\.exe|powershell|/bin/sh|/bin/bash)"
  }

  tags = {
    Name        = "${var.waf_name[local.workspace]}-malicious-patterns"
    Environment = local.workspace
  }
}

# WAF Logging Configuration (same as before)
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_log_group.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

# CloudWatch Log Group for WAF Logs (same as before)
resource "aws_cloudwatch_log_group" "waf_log_group" {
  name              = "aws-waf-logs-${var.waf_name[local.workspace]}"
  retention_in_days = 30

  tags = {
    Name        = "${var.waf_name[local.workspace]}-logs"
    Environment = local.workspace
  }
}

# Outputs (same as before)
output "waf_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "waf_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.id
}

output "waf_name" {
  description = "Name of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.name
}