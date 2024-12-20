terraform {
  required_providers {
    st-digicert = {
      source  = "example.local/myklst/st-digicert"
      version = "~> 0.1"
    }
  }
}

resource "st-digicert_certificate" "certificate" {
  common_name        = "abc.com"
  sans               = ["*.abc.com"]
  organization_id    = 2918233
  min_days_remaining = 30
  product_name       = "GeoTrust TrueBusiness ID OV"

  dns_challenge {
    provider = "route53"
    config = {
      AWS_ACCESS_KEY_ID     = "xxx"
      AWS_SECRET_ACCESS_KEY = "xxx"
    }
  }
}
