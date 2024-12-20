// Copyright (c) HashiCorp, Inc.

package cloudflaredns

import (
	"github.com/cloudflare/cloudflare-go"
)

type Cloudflare struct {
	Client *cloudflare.API
}

func NewClient(apiToken string) (cf *Cloudflare, err error) {
	client, err := cloudflare.NewWithAPIToken(apiToken)
	return &Cloudflare{
		Client: client,
	}, err
}
