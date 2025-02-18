// Copyright (c) HashiCorp, Inc.

package digicert

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var (
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"st-digicert": providerserver.NewProtocol6WithError(New("test")()),
	}
)
