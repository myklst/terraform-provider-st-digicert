// Copyright (c) HashiCorp, Inc.

package route53

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
)

func NewClient(accessKey, secretKey string) (*Rout53, error) {
	if accessKey == "" {
		return nil, fmt.Errorf("aws newClient(): missing access_key")
	}
	if secretKey == "" {
		return nil, fmt.Errorf("aws newClient(): missing secret_key")
	}

	svcEndpoint := "route53.amazonaws.com"
	// Route53 is global, need to use specified region to query.
	region := "us-east-1"
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
		Endpoint:    &svcEndpoint,
		Region:      &region,
	})
	if err != nil {
		return nil, err
	}

	return &Rout53{
		Client: route53.New(sess),
	}, nil
}
