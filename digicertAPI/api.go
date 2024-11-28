// Copyright (c) HashiCorp, Inc.

package digicertapi

import (
	"fmt"
	"net/http"
)

const (
	GEOTRUST_TRUEBUSINESS_ID_OV_ENDPOINT = "https://www.digicert.com/services/v2/order/certificate/ssl_geotrust_truebizid"
	ORDER_ENDPOINT                       = "https://www.digicert.com/services/v2/order/certificate"
	CERT_ENDPOINT                        = "https://www.digicert.com/services/v2/certificate"
	PRODUCT_ENDPOINT                     = "https://www.digicert.com/services/v2/product"
	INTERMEDIATE_ENDPOINT                = "https://www.digicert.com/services/v2/certificate/intermediates"
	DOMAIN_ENDPOINT                      = "https://www.digicert.com/services/v2/domain"
	REQUEST_ENDPOINT                     = "https://www.digicert.com/services/v2/request"
)

func (c *Client) GetOrgInfoByID(orgId int) (resp []byte, err error) {
	url := fmt.Sprintf("https://www.digicert.com/services/v2/organization/%d", orgId)
	return c.httpResponse(http.MethodGet, url, nil)
}

func (c *Client) IssueCert(payload []byte, productName string) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%s", ORDER_ENDPOINT, productName)
	return c.httpResponse(http.MethodPost, url, payload)
}

func (c *Client) ReissueCert(orderId int, payload []byte) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d/reissue", ORDER_ENDPOINT, orderId)
	return c.httpResponse(http.MethodPost, url, payload)
}

func (c *Client) RevokeCert(certId int, payload []byte) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d/revoke", CERT_ENDPOINT, certId)

	return c.httpResponse(http.MethodPut, url, payload)
}

func (c *Client) RevokeAllCert(orderId int, payload []byte) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d/revoke", ORDER_ENDPOINT, orderId)

	return c.httpResponse(http.MethodPut, url, payload)
}

func (c *Client) GetOrders(commonName string) (resp []byte, err error) {
	url := fmt.Sprintf("%s?filters[status]=issued&sort=-date_created&filters[common_name]=%s", ORDER_ENDPOINT, commonName)
	return c.httpResponse(http.MethodGet, url, nil)
}

func (c *Client) GetOrdersList() (resp []byte, err error) {
	url := fmt.Sprintf("%s?filters[status]=issued", ORDER_ENDPOINT)
	return c.httpResponse(http.MethodGet, url, nil)
}

func (c *Client) GetOrderInfo(orderId int) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d", ORDER_ENDPOINT, orderId)

	return c.httpResponse(http.MethodGet, url, nil)
}

func (c *Client) UpdateOrderStatus(orderId int, payload []byte) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d/status", ORDER_ENDPOINT, orderId)
	return c.httpResponse(http.MethodPut, url, payload)
}

func (c *Client) GetProductList() (resp []byte, err error) {
	return c.httpResponse(http.MethodGet, PRODUCT_ENDPOINT, nil)
}

func (c *Client) GetIntermediateList() (resp []byte, err error) {
	return c.httpResponse(http.MethodGet, INTERMEDIATE_ENDPOINT, nil)
}

func (c *Client) AddDomain(payload []byte) (resp []byte, err error) {
	return c.httpResponse(http.MethodPost, DOMAIN_ENDPOINT, payload)
}

func (c *Client) GetDomainsList() (resp []byte, err error) {
	return c.httpResponse(http.MethodGet, DOMAIN_ENDPOINT, nil)
}

func (c *Client) GetDomainInfo(domainID int) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d?include_dcv=true&include_validation=true", DOMAIN_ENDPOINT, domainID)
	return c.httpResponse(http.MethodGet, url, nil)
}

func (c *Client) CheckDomainDCV(domainID int) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d/dcv/validate-token", DOMAIN_ENDPOINT, domainID)
	return c.httpResponse(http.MethodPut, url, nil)
}

func (c *Client) GetCertificateChain(certID int) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d/chain", CERT_ENDPOINT, certID)
	return c.httpResponse(http.MethodGet, url, nil)
}

func (c *Client) GetRequestInfo(requestID int) (resp []byte, err error) {
	url := fmt.Sprintf("%s/%d", REQUEST_ENDPOINT, requestID)
	return c.httpResponse(http.MethodGet, url, nil)
}
