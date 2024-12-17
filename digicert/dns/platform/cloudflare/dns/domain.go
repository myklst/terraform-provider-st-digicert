// Copyright (c) HashiCorp, Inc.

package cloudflaredns

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/cloudflare/cloudflare-go"
	"github.com/myklst/terraform-provider-st-digicert/digicert/backoff_retry"
)

const (
	MAX_ELAPSED_TIME = 5 * time.Minute // clouflare API rate limit, 1200 requests per five minute
)

func (c *Cloudflare) createDNSRecord(domainName, recordName, content, rrType string, ttl int) (dnsRecordID string, err error) {
	zoneID, err := c.Client.ZoneIDByName(domainName)
	if err != nil {
		return "", nil
	}

	createDNS := cloudflare.CreateDNSRecordParams{
		Type: rrType,
		Name: recordName,
		// Value need to be enclosed in double marks. `"verify_txt_record_123456"`.
		Content: fmt.Sprintf("%q", content),
		TTL:     ttl,
	}

	var dnsRecord cloudflare.DNSRecord
	createDNSRecord := func() error {
		dnsRecord, err = c.Client.CreateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), createDNS)
		if err != nil {
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(createDNSRecord, MAX_ELAPSED_TIME); err != nil {
		return "", fmt.Errorf("createDNSRecord() Failed to create dns records on cloudflare: %v", err)
	}

	return dnsRecord.ID, nil
}

func (c *Cloudflare) getDNSRecordsByDomainName(domainName string) (dnsRecords []cloudflare.DNSRecord, err error) {
	zoneID, err := c.Client.ZoneIDByName(domainName)
	if err != nil {
		return dnsRecords, nil
	}

	listDNSRercords := func() error {
		dnsRecords, _, err = c.Client.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{})
		if err != nil {
			return err
		}
		return nil
	}
	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = MAX_ELAPSED_TIME
	if err := backoff.Retry(listDNSRercords, reconnectBackoff); err != nil {
		return dnsRecords, fmt.Errorf("listDNSRercords() Failed to list dns records on cloudflare: %v", err)
	}

	return dnsRecords, nil
}

func (c *Cloudflare) updateDNSRecord(domainName, id, recordName, content, rrType string, ttl int) (err error) {
	zoneID, err := c.Client.ZoneIDByName(domainName)
	if err != nil {
		return nil
	}

	updateDns := cloudflare.UpdateDNSRecordParams{
		ID:   id,
		Type: rrType,
		Name: recordName,
		// Value need to be enclosed in double marks. `"verify_txt_record_123456"`.
		Content: fmt.Sprintf("%q", content),
		TTL:     ttl,
	}

	updateDNSRercords := func() error {
		if _, err := c.Client.UpdateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), updateDns); err != nil {
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(updateDNSRercords, MAX_ELAPSED_TIME); err != nil {
		return fmt.Errorf("updateDNSRercords() Failed to update dns records on cloudflare: %v", err)
	}
	return nil
}

func (c *Cloudflare) DeleteDnsRecord(recordId, domainName string) (err error) {
	zoneID, err := c.Client.ZoneIDByName(domainName)
	if err != nil {
		return nil
	}

	deleteDNSRercords := func() error {
		if err := c.Client.DeleteDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), recordId); err != nil {
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(deleteDNSRercords, MAX_ELAPSED_TIME); err != nil {
		return fmt.Errorf("DeleteDNSRercords() Failed to delete dns record on cloudflare: %v", err)
	}

	return nil
}

func (c *Cloudflare) UpdateRecord(domainName, token string) (dnsRecordID string, err error) {
	dnsRecords, err := c.getDNSRecordsByDomainName(domainName)
	if err != nil {
		return "", err
	}
	if len(dnsRecords) == 0 {
		return "", fmt.Errorf("no DNS records were found")
	}

	ttl := 300
	for _, dnsRecord := range dnsRecords {
		if dnsRecord.Type == "TXT" {
			// Upated
			if err := c.updateDNSRecord(domainName, dnsRecord.ID, domainName, token, dnsRecord.Type, ttl); err != nil {
				return "", err
			}
			return dnsRecord.ID, nil
		}
	}

	dnsRecordID, err = c.createDNSRecord(domainName, domainName, token, "TXT", ttl)
	if err != nil {
		return "", err
	}

	return dnsRecordID, nil
}
