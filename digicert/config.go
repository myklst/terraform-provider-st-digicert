// Copyright (c) HashiCorp, Inc.

package digicert

import (
	"fmt"

	digicertapi "github.com/myklst/terraform-provider-st-digicert/digicertAPI"
)

type Config struct {
	ApiKey string
}

func (c *Config) Client() (*digicertapi.Client, error) {
	client, err := digicertapi.NewClient(c.ApiKey)

	if err != nil {
		return nil, fmt.Errorf("error setting up client: %s", err)
	}

	return client, nil
}
