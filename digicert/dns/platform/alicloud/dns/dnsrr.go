// Copyright (c) HashiCorp, Inc.

package dns

import (
	"context"
	"fmt"
	"time"

	alidns "github.com/alibabacloud-go/alidns-20150109/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/myklst/terraform-provider-st-digicert/digicert/dns/platform/alicloud"
)

type Alidns struct {
	Client *alidns.Client
}

func (a *Alidns) GetAllDnsRecords(domain string) (domainRecords []*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, err error) {
	describeDomainRecordsRequest := &alidns.DescribeDomainRecordsRequest{
		DomainName: tea.String(domain),
		PageSize:   tea.Int64(500), // AliCloud maximum allow 500 records. It's
		// quiet a lot for now, so we don't do paging
		// process first.
	}

	response, err := a.Client.DescribeDomainRecords(describeDomainRecordsRequest)
	if err != nil {
		return nil, err
	}

	return response.Body.DomainRecords.Record, err
}

func (a *Alidns) GetDnsRecord(domain, rrType, subdomain string) (domainRecords []*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, err error) {
	describeDomainRecordsRequest := &alidns.DescribeDomainRecordsRequest{
		DomainName:  tea.String(domain),
		TypeKeyWord: tea.String(rrType),
		RRKeyWord:   tea.String(subdomain),
	}

	response, err := a.Client.DescribeDomainRecords(describeDomainRecordsRequest)
	if err != nil {
		return nil, err
	}

	return response.Body.DomainRecords.Record, nil
}

func (a *Alidns) AddDnsRecord(domain, rrType, rr, value string) (recordID string, err error) {
	addDomainRecordRequest := &alidns.AddDomainRecordRequest{
		DomainName: tea.String(domain),
		RR:         tea.String(rr),
		Type:       tea.String(rrType),
		Value:      tea.String(value),
	}

	response, err := a.Client.AddDomainRecord(addDomainRecordRequest)
	if err != nil {
		return "", err
	}

	return *response.Body.RecordId, nil
}

func (a *Alidns) UpdateDnsRecord(id, rrType, subdomain, value string) (err error) {
	updateDomainRecordRequest := &alidns.UpdateDomainRecordRequest{
		RecordId: tea.String(id),
		RR:       tea.String(subdomain),
		Type:     tea.String(rrType),
		Value:    tea.String(value),
	}

	if _, err := a.Client.UpdateDomainRecord(updateDomainRecordRequest); err != nil {
		return err
	}

	return nil
}

func (a *Alidns) DeleteDnsRecord(id string) (err error) {
	deleteDomainRecordRequest := &alidns.DeleteDomainRecordRequest{
		RecordId: tea.String(id),
	}

	if _, err := a.Client.DeleteDomainRecord(deleteDomainRecordRequest); err != nil {
		return err
	}

	return nil
}

func (a *Alidns) CreateAliDNSRecord(commonName string, token string) (recordId string, err error) {
	dnsRecords, err := a.GetAllDnsRecords(commonName)
	if err != nil {
		return "", err
	}

	if len(dnsRecords) == 0 {
		return "", fmt.Errorf("domain name not found in AWS route53")
	}

	var foundDnsRecord *alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord
	for _, dnsRecord := range dnsRecords {
		if *dnsRecord.DomainName == commonName && *dnsRecord.RR == "@" && *dnsRecord.Type == "TXT" {
			foundDnsRecord = dnsRecord
			break
		}
	}

	// Record not found
	if foundDnsRecord == nil {
		// Create a TXT record
		addRecord := func() error {
			recordId, err = a.AddDnsRecord(commonName, "TXT", "@", token)
			if err != nil {
				tflog.Debug(context.Background(), fmt.Sprintf("Alidns Add record Error: %s", err.Error()))
				if alicloud.IsPermanentCommonError(err.Error()) {
					return backoff.Permanent(err)
				}
				return err
			}
			return nil
		}

		reconnectBackoff := backoff.NewExponentialBackOff()
		reconnectBackoff.MaxElapsedTime = 10 * time.Minute
		if err := backoff.Retry(addRecord, reconnectBackoff); err != nil {
			return "", fmt.Errorf("Alidns create dns record. Failed to create verification TXT record: %v", err)
		}
		return recordId, nil
	}

	// Update the existed TXT record
	updateRecord := func() error {
		if err := a.UpdateDnsRecord(*foundDnsRecord.RecordId, *foundDnsRecord.Type, *foundDnsRecord.RR, token); err != nil {
			tflog.Debug(context.Background(), fmt.Sprintf("Alidns update record Error: %s", err.Error()))
			if alicloud.IsPermanentCommonError(err.Error()) {
				return backoff.Permanent(err)
			}
			return err
		}
		return nil
	}

	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = 10 * time.Minute
	if err := backoff.Retry(updateRecord, reconnectBackoff); err != nil {
		return "", fmt.Errorf("Alidns update dns record. Failed to Update verification TXT record: %v", err)
	}

	return *foundDnsRecord.RecordId, nil
}
