# Copyright (c) HashiCorp, Inc.

terraform {
  required_providers {
    st-digicert = {
      source  = "myklst/st-digicert"
      version = "~> 0.1"
    }
  }
}

provider "st-digicert" {
  api_key = "xxx"
}
