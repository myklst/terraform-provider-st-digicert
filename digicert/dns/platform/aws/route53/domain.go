// Copyright (c) HashiCorp, Inc.

package route53

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/myklst/terraform-provider-st-digicert/digicert/backoff_retry"
	awsErrCommon "github.com/myklst/terraform-provider-st-digicert/digicert/dns/platform/aws"
	"github.com/sirupsen/logrus"
)

const (
	CREATE_RECORD    = "CREATE"
	DELETE_RECORD    = "DELETE"
	UPSERT_RECORD    = "UPSERT"
	MAX_ELAPSED_TIME = 10 * time.Minute
)

type Rout53 struct {
	Client *route53.Route53
}

func (r *Rout53) GetHostedZoneByDomainName(domain string) (hostedZoneIds []string, err error) {
	domain = fmt.Sprintf("%s.", domain) // AWS hosted zone format, Ensure the domain name ends with a dot (.)

	req := &route53.ListHostedZonesByNameInput{
		DNSName:  aws.String(domain),
		MaxItems: aws.String("1"),
	}

	for {
		var result *route53.ListHostedZonesByNameOutput
		listHostedZonesByName := func() error {
			result, err = r.Client.ListHostedZonesByName(req)
			if err != nil {
				logrus.Errorf("Failed to list hosted zones by name: %v", err)
				if aerr, ok := err.(awserr.Error); ok {
					errCode := aerr.Code()
					tflog.Debug(context.Background(), fmt.Sprintf("AWS Route53 list hosted zones by name Error: %s", err.Error()))
					if awsErrCommon.IsPermanentCommonError(errCode) {
						return backoff.Permanent(fmt.Errorf("permanent err:\n%w", aerr))
					}
					return aerr
				}
				return err
			}
			return nil
		}
		if err := backoff_retry.RetryOperator(listHostedZonesByName, MAX_ELAPSED_TIME); err != nil {
			return hostedZoneIds, fmt.Errorf("ListHostedZonesByName() Failed to list hosted zone by name: %v", err)
		}

		for _, zone := range result.HostedZones {
			hostedZoneIds = append(hostedZoneIds, aws.StringValue(zone.Id))
		}

		// Check if the result is truncated and set the req for the next iteration
		if *result.IsTruncated {
			if aws.StringValue(result.NextDNSName) != domain {
				break
			}
		} else {
			break
		}

		req.DNSName = result.NextDNSName
		req.HostedZoneId = result.NextHostedZoneId
	}

	return hostedZoneIds, nil
}

func (r *Rout53) changeResourceRecordSets(action, domain, verifyTxtContent, hostedZoneId string) (resp *route53.ChangeResourceRecordSetsOutput, err error) {
	req := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneId),
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action: aws.String(action),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(domain),
						Type: aws.String("TXT"),
						TTL:  aws.Int64(300),
						ResourceRecords: []*route53.ResourceRecord{
							{
								// Value need to be enclosed in double marks. `"verify_txt_record_123456"`.
								Value: aws.String(fmt.Sprintf("%q", verifyTxtContent)),
							},
						},
					},
				},
			},
		},
	}

	changeRecord := func() error {
		if resp, err = r.Client.ChangeResourceRecordSets(req); err != nil {
			logrus.Errorf("Failed to %s verification records: %v", "UPSERT", err)
			if aerr, ok := err.(awserr.Error); ok {
				errCode := aerr.Code()
				tflog.Debug(context.Background(), fmt.Sprintf("AWS Route53 modify record Error: %s", err.Error()))
				if awsErrCommon.IsPermanentCommonError(errCode) {
					return backoff.Permanent(fmt.Errorf("permanent err:\n%w", aerr))
				}
				return aerr
			}
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(changeRecord, MAX_ELAPSED_TIME); err != nil {
		return resp, fmt.Errorf("modifyRoute53Record() Failed to create verification TXT record: %v", err)
	}

	return resp, nil
}

func (r *Rout53) ModifyAWSRoute53Record(action, commonName, token string, hostedZoneIds []string) (err error) {
	for _, hostedZoneId := range hostedZoneIds {
		if _, err := r.changeResourceRecordSets(action, commonName, token, hostedZoneId); err != nil {
			logrus.Errorf("Failed to %s verification records: %v", "UPSERT", err)
			return err
		}
	}

	return nil
}
