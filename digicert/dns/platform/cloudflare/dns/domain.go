// Copyright (c) HashiCorp, Inc.

package cloudflaredns

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/myklst/terraform-provider-st-digicert/digicert/backoff_retry"
	"github.com/sirupsen/logrus"
)

const (
	MAX_ELAPSED_TIME = 10 * time.Minute
)

func (c *Cloudflare) getZoneIDByName(domainName string) (zoneID string, err error) {
	getZoneID := func() error {
		if zoneID, err = c.Client.ZoneIDByName(domainName); err != nil {
			logrus.Errorf("Cloudflare Failed to get zone id by name: %v", err)
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(getZoneID, MAX_ELAPSED_TIME); err != nil {
		return "", fmt.Errorf("Cloudflare getZoneIDByName() Failed to get zone ID: %v", err)
	}

	return zoneID, nil
}

func (c *Cloudflare) createDNSRecord(domainName, recordName, content, rrType string, ttl int) (dnsRecordID string, err error) {
	zoneID, err := c.getZoneIDByName(domainName)
	if err != nil {
		return "", err
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
		if dnsRecord, err = c.Client.CreateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), createDNS); err != nil {
			logrus.Errorf("Cloudflare Failed to create DNS record: %v", err)
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(createDNSRecord, MAX_ELAPSED_TIME); err != nil {
		return "", fmt.Errorf("Cloudflare createDNSRecord() Failed to create dns records: %v", err)
	}

	return dnsRecord.ID, nil
}

func (c *Cloudflare) getDNSRecordsByDomainName(domainName string) (dnsRecords []cloudflare.DNSRecord, err error) {
	zoneID, err := c.getZoneIDByName(domainName)
	if err != nil {
		return dnsRecords, err
	}

	listDNSRercords := func() error {
		if dnsRecords, _, err = c.Client.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{}); err != nil {
			logrus.Errorf("Cloudflare Failed to list dns records: %v", err)
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(listDNSRercords, MAX_ELAPSED_TIME); err != nil {
		return dnsRecords, fmt.Errorf("Cloudflare listDNSRercords() Failed to list DNS records: %v", err)
	}

	return dnsRecords, nil
}

func (c *Cloudflare) updateDNSRecord(domainName, id, recordName, content, rrType string, ttl int) (err error) {
	zoneID, err := c.getZoneIDByName(domainName)
	if err != nil {
		return err
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
			logrus.Errorf("Cloudflare Failed to update dns record: %v", err)
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(updateDNSRercords, MAX_ELAPSED_TIME); err != nil {
		return fmt.Errorf("Cloudflare updateDNSRercords() Failed to update dns records: %v", err)
	}
	return nil
}

func (c *Cloudflare) DeleteDnsRecord(recordId, domainName string) (err error) {
	zoneID, err := c.getZoneIDByName(domainName)
	if err != nil {
		return err
	}

	deleteDNSRercords := func() error {
		if err := c.Client.DeleteDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), recordId); err != nil {
			logrus.Errorf("Cloudflare Failed to delete dns record: %v", err)
			return err
		}
		return nil
	}
	if err := backoff_retry.RetryOperator(deleteDNSRercords, MAX_ELAPSED_TIME); err != nil {
		return fmt.Errorf("Cloudflare deleteDNSRercords() Failed to delete dns record: %v", err)
	}

	return nil
}

func (c *Cloudflare) UpdateRecord(domainName, token string) (dnsRecordID string, err error) {
	dnsRecords, err := c.getDNSRecordsByDomainName(domainName)
	if err != nil {
		return "", err
	}
	if len(dnsRecords) == 0 {
		return "", fmt.Errorf("Cloudflare No DNS records were found")
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
