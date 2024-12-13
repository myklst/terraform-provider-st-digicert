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
	awsErrCommon "github.com/myklst/terraform-provider-st-digicert/digicert/dns/platform/aws"
	"github.com/sirupsen/logrus"
)

const (
	CREATE_RECORD = "CREATE"
	DELETE_RECORD = "DELETE"
	UPSERT_RECORD = "UPSERT"
)

type Rout53 struct {
	Client *route53.Route53
}

func (r *Rout53) ListAllDomains() (hostedZoneList []*route53.HostedZone, err error) {
	listHostedZonesInputRequest := &route53.ListHostedZonesInput{}

	for {
		result, err := r.Client.ListHostedZones(listHostedZonesInputRequest)
		if err != nil {
			return nil, err
		}

		// Store the hosted zones from the current page.
		hostedZoneList = append(hostedZoneList, result.HostedZones...)

		// If there are more pages, set the marker to the NextMarker from the current page
		if *result.IsTruncated {
			listHostedZonesInputRequest.Marker = result.NextMarker
		} else {
			// If there are no more pages, break out of the loop
			break
		}
	}

	return hostedZoneList, nil
}

func (r *Rout53) GetHostedZoneByDomainName(domain string) (hostedZoneIds []string, err error) {
	domain = fmt.Sprintf("%s.", domain) // AWS hosted zone format, Ensure the domain name ends with a dot (.)

	listHostedZonesByNameInputRequest := &route53.ListHostedZonesByNameInput{
		DNSName:  aws.String(domain),
		MaxItems: aws.String("1"),
	}

	for {
		result, err := r.Client.ListHostedZonesByName(listHostedZonesByNameInputRequest)
		if err != nil {
			return nil, err
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

		listHostedZonesByNameInputRequest.DNSName = result.NextDNSName
		listHostedZonesByNameInputRequest.HostedZoneId = result.NextHostedZoneId
	}

	return hostedZoneIds, nil
}

func (r *Rout53) ListReusableDelegationSets() (listReusableDelegationSetsRequest *route53.ListReusableDelegationSetsOutput, err error) {
	listReusableDelegationSetsRequest, err = r.Client.ListReusableDelegationSets(&route53.ListReusableDelegationSetsInput{})
	if err != nil {
		return nil, err
	}

	return listReusableDelegationSetsRequest, nil
}

func (r *Rout53) CreateHostedZone(domain, delegationSetId string) (resp *route53.CreateHostedZoneOutput, err error) {
	createHostedZoneInput := &route53.CreateHostedZoneInput{
		Name:            aws.String(domain),
		DelegationSetId: aws.String(delegationSetId),
		// Required: CallerReference, used unique timestamp for request.
		CallerReference: aws.String(time.Unix(time.Now().Unix(), 0).Format("2006-01-02 15:04:05 MST")),
	}

	resp, err = r.Client.CreateHostedZone(createHostedZoneInput)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (r *Rout53) DeleteHostedZone(hostedZoneId string) (resp *route53.DeleteHostedZoneOutput, err error) {
	deleteHostedZoneInput := &route53.DeleteHostedZoneInput{
		Id: aws.String(hostedZoneId),
	}

	resp, err = r.Client.DeleteHostedZone(deleteHostedZoneInput)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (r *Rout53) ChangeResourceRecordSets(action, domain, verifyTxtContent, hostedZoneId string) (resp *route53.ChangeResourceRecordSetsOutput, err error) {
	changeResourceRecordSetsInput := &route53.ChangeResourceRecordSetsInput{
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

	resp, err = r.Client.ChangeResourceRecordSets(changeResourceRecordSetsInput)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (r *Rout53) ModifyAWSRoute53Record(action, commonName, token string, hostedZoneIds []string) (err error) {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 10 * time.Minute // Set maximum wait time to 10 minutes

	for _, hostedZoneId := range hostedZoneIds {
		changeRecord := func() error {
			if _, err := r.ChangeResourceRecordSets(action, commonName, token, hostedZoneId); err != nil {
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

		reconnectBackoff := backoff.NewExponentialBackOff()
		reconnectBackoff.MaxElapsedTime = 10 * time.Minute
		if err := backoff.Retry(changeRecord, reconnectBackoff); err != nil {
			return fmt.Errorf("modifyRoute53Record() Failed to create verification TXT record: %v", err)
		}
	}

	return nil
}
