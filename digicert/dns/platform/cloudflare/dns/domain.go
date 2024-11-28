// Copyright (c) HashiCorp, Inc.

package cloudflaredns

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
)

func (c *Cloudflare) CreateDNSRecord(domainName, recordName, content, rrType string, ttl int) (dnsRecordID string, err error) {
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
	dnsRecord, err := c.Client.CreateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), createDNS)
	if err != nil {
		return "", err
	}

	return dnsRecord.ID, nil
}

func (c *Cloudflare) GetDNSRecordsByDomainName(domainName string) (dnsRecords []cloudflare.DNSRecord, err error) {
	zoneID, err := c.Client.ZoneIDByName(domainName)
	if err != nil {
		return dnsRecords, nil
	}

	dnsRecords, _, err = c.Client.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{})
	if err != nil {
		return dnsRecords, err
	}

	return dnsRecords, nil
}

func (c *Cloudflare) UpdateDNSRecord(domainName, id, recordName, content, rrType string, ttl int) error {
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
	if _, err := c.Client.UpdateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), updateDns); err != nil {
		return err
	}

	return nil
}

func (c *Cloudflare) DeleteDnsRecord(recordId, domainName string) error {
	zoneID, err := c.Client.ZoneIDByName(domainName)
	if err != nil {
		return nil
	}

	if err := c.Client.DeleteDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), recordId); err != nil {
		return err
	}

	return nil
}

func (c *Cloudflare) UpdateRecord(domainName, token string) (dnsRecordID string, err error) {
	dnsRecords, err := c.GetDNSRecordsByDomainName(domainName)
	if err != nil {
		return "", err
	}

	if len(dnsRecords) == 0 {
		return "", fmt.Errorf("no DNS records were found")
	}

	for _, dnsRecord := range dnsRecords {
		if dnsRecord.Type == "TXT" {
			// Upated
			if err := c.UpdateDNSRecord(domainName, dnsRecord.ID, domainName, token, dnsRecord.Type, 300); err != nil {
				return "", err
			}
			return dnsRecord.ID, nil
		}
	}

	dnsRecordID, err = c.CreateDNSRecord(domainName, domainName, token, "TXT", 300)
	if err != nil {
		return "", err
	}

	return dnsRecordID, nil
}
