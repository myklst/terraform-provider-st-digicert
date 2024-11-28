// Copyright (c) HashiCorp, Inc.

package cloudflaredns

import (
	"github.com/cloudflare/cloudflare-go"
)

type Cloudflare struct {
	Client *cloudflare.API
}

func NewClient(apiToken string) (*Cloudflare, error) {
	client, err := cloudflare.NewWithAPIToken(apiToken)
	if err != nil {
		return nil, err
	}
	return &Cloudflare{
		Client: client,
	}, nil
}
