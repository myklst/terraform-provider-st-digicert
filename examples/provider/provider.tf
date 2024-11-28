# Configure the Digicert Provider

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
