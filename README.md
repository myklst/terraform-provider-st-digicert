# terraform-provider-st-digicert

This Terraform custom provider is designed for own use case scenario.

Supported Versions
------------------

| Terraform version | minimum provider version |maxmimum provider version
| ---- | ---- | ----|
| >= 1.3.x | 0.1.0 | latest |

Requirements
------------

- [Terraform](https://www.terraform.io/downloads.html) 1.3.x
- [Go](https://golang.org/doc/install) 1.23 (to build the provider plugin)

Local Installation
------------------

1. Run `make install-local-custom-provider` to install the provider under ~/.terraform.d/plugins.

2. The provider source should be change to the path that configured in the *Makefile*:

    ```
    terraform {
      required_providers {
        st-digicert = {
          source = "example.local/myklst/st-digicert"
        }
      }
    }

    provider "st-digicert" {}
    ```

Why Custom Provider
-------------------

Digicert does not support managing resources with Terraform.


References
----------

- Terraform website: https://www.terraform.io
- Terraform Plugin Framework: https://developer.hashicorp.com/terraform/tutorials/providers-plugin-framework
- Digicert API documentation: https://dev.digicert.com/en/certcentral-apis/services-api.html
