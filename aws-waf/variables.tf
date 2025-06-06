# Variables
variable "waf_name" {
  description = "Override default WAF name"
  type        = map(string)
  default = {
    stg  = "stg-seek-waf"
    dev  = "dev-seek-waf"
    prd  = "prd-seek-waf"
    cloud  = "prd-cloudconsul-waf"
    knprd = "knprd-datahub-waf"
  }
}

variable "waf_scope" {
  description = "WAF scope - REGIONAL for ALB/API Gateway, CLOUDFRONT for CloudFront"
  type        = string
  default     = "REGIONAL"
}


