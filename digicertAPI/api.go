// Copyright (c) HashiCorp, Inc.

package digicertapi

import (
	"encoding/json"
	"errors"
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
	ORGANIZATION_ENDPOINT                = "https://www.digicert.com/services/v2/organization"
)

type CertificatePayload struct {
	ID               int                `json:"certificate_id"`
	Organization     Organization       `json:"organization"`
	CommonName       string             `json:"common_name"`
	DNSNames         []string           `json:"dns_names"`
	CSR              string             `json:"csr"`
	SignatureHash    string             `json:"signature_hash"`
	CACertID         string             `json:"ca_cert_id"`
	CertificateChain []CertificateChain `json:"certificate_chain"`
	Error            []ErrorMsg         `json:"errors"`
	PrivateKey       string             `json:"-"`
}

type Organization struct {
	ID int `json:"id"`
}

type OrderValidityPayload struct {
	Days int `json:"days,omitempty"`
}

type OrderPayload struct {
	Certificate      CertificatePayload   `json:"certificate"`
	Organization     Organization         `json:"organization"`
	OrderValidity    OrderValidityPayload `json:"order_validity,omitempty"`
	PaymentMethod    string               `json:"payment_method"`
	RenewalOfOrderID int                  `json:"renewal_of_order_id"`
	DcvMethod        string               `json:"dcv_method"`
}

type DomainRespBody struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	DcvToken DcvToken `json:"dcv_token"`
}

type IssueCertRespBody struct {
	OrderID              int                `json:"id"`
	CertificateID        int                `json:"certificate_id"`
	CertificateChain     []CertificateChain `json:"certificate_chain"`
	Domains              []DomainRespBody   `json:"domains"`
	SubjectCommonName    string             `json:"subject_common_name"`
	OrderValidTill       string             `json:"order_valid_till"`
	DcvRandomValue       string             `json:"dcv_random_value"`
	PrivateKey           string             `json:"-"`
	CertificateValidTill string             `json:"-"`
	OrderValidTillDay    int                `json:"-"`
	ErrorMsg             []ErrorMsg         `json:"errors"`
}

func (c *Client) IssueCert(orderPayLoad OrderPayload) (issueCert IssueCertRespBody, err error) {
	url := fmt.Sprintf("%s/%s", ORDER_ENDPOINT, orderPayLoad.Certificate.CACertID)
	jsonPayload, err := json.Marshal(orderPayLoad)
	if err != nil {
		return IssueCertRespBody{}, err
	}

	resp, err := c.httpResponse(http.MethodPost, url, jsonPayload)
	if err != nil {
		return IssueCertRespBody{}, err
	}

	if err := json.Unmarshal(resp, &issueCert); err != nil {
		return IssueCertRespBody{}, err
	}

	if len(issueCert.ErrorMsg) != 0 {
		return IssueCertRespBody{}, fmt.Errorf("error issue certificate, error: %s", fmt.Sprintf("%s. %s",
			issueCert.ErrorMsg[0].Code, issueCert.ErrorMsg[0].Message))
	}

	return issueCert, nil
}

func (c *Client) ReissueCert(orderPayload OrderPayload, orderID int) (issueCert IssueCertRespBody, err error) {
	url := fmt.Sprintf("%s/%d/reissue", ORDER_ENDPOINT, orderID)
	jsonPayload, err := json.Marshal(orderPayload)
	if err != nil {
		return IssueCertRespBody{}, err
	}

	resp, err := c.httpResponse(http.MethodPost, url, jsonPayload)
	if err != nil {
		return IssueCertRespBody{}, err
	}

	if err = json.Unmarshal(resp, &issueCert); err != nil {
		return IssueCertRespBody{}, err
	}

	if len(issueCert.ErrorMsg) != 0 {
		return IssueCertRespBody{}, fmt.Errorf("error reissue certificate, error: %s", fmt.Sprintf("%s. %s",
			issueCert.ErrorMsg[0].Code, issueCert.ErrorMsg[0].Message))
	}

	return issueCert, nil
}

type OrderRespBody struct {
	ID             int         `json:"id"`
	Certificate    Certificate `json:"certificate"`
	Status         string      `json:"status"`
	OrderValidTill string      `json:"order_valid_till"`
	IsRenewed      bool        `json:"is_renewed"`
	ErrorMsg       []ErrorMsg  `json:"errors"`
}

func (c *Client) GetOrderInfo(orderId int) (order OrderRespBody, err error) {
	url := fmt.Sprintf("%s/%d", ORDER_ENDPOINT, orderId)
	resp, err := c.httpResponse(http.MethodGet, url, nil)
	if err != nil {
		return OrderRespBody{}, err
	}

	if err := json.Unmarshal(resp, &order); err != nil {
		return OrderRespBody{}, err
	}

	return order, err
}

type OrderListRespBody struct {
	Orders   []OrderRespBody `json:"orders"`
	ErrorMsg []ErrorMsg      `json:"errors"`
}

func (c *Client) GetOrders(commonName string) (orders OrderListRespBody, err error) {
	url := fmt.Sprintf("%s?filters[status]=issued&sort=-date_created&filters[common_name]=%s", ORDER_ENDPOINT, commonName)
	resp, err := c.httpResponse(http.MethodGet, url, nil)
	if err != nil {
		return OrderListRespBody{}, err
	}

	if err := json.Unmarshal(resp, &orders); err != nil {
		return OrderListRespBody{}, err
	}

	// Check if any error msg return from API
	for _, errormsg := range orders.ErrorMsg {
		return OrderListRespBody{}, errors.New(errormsg.Message)
	}

	return orders, nil
}

type CertificateChain struct {
	SubjectCommonName string `json:"subject_common_name"`
	Pem               string `json:"pem"`
}

type Certificate struct {
	ID               int                `json:"id"`
	Status           string             `json:"status"`
	CommonName       string             `json:"common_name"`
	ValidTill        string             `json:"valid_till"`
	CertificateChain []CertificateChain `json:"certificate_chain"`
	Organization     Organization       `json:"organization"`
	CSR              string             `json:"csr"`
	PrivateKey       string             `json:"-"`
	CertificatePem   string             `json:"-"`
	IssuerPem        string             `json:"-"`
	RootPem          string             `json:"-"`
}

type CertificateChainList struct {
	CertificateChain []CertificateChain `json:"intermediates"`
}

func (c *Client) GetCertificateChain(certID int) (certificateChains []CertificateChain, err error) {
	url := fmt.Sprintf("%s/%d/chain", CERT_ENDPOINT, certID)
	resp, err := c.httpResponse(http.MethodGet, url, nil)
	if err != nil {
		return []CertificateChain{}, err
	}

	var certificateChainList CertificateChainList
	if err := json.Unmarshal(resp, &certificateChainList); err != nil {
		return []CertificateChain{}, err
	}

	return certificateChainList.CertificateChain, nil
}

type IntermediateListRespBody struct {
	Intermediates []Intermediates `json:"intermediates"`
}

type Intermediates struct {
	SubjectCommonName string `json:"subject_common_name"`
	IssuerCommonName  string `json:"issuer_common_name"`
}

func (c *Client) GetIntermediateList() (intermediateList IntermediateListRespBody, err error) {
	resp, err := c.httpResponse(http.MethodGet, INTERMEDIATE_ENDPOINT, nil)
	if err != nil {
		return IntermediateListRespBody{}, err
	}

	if err := json.Unmarshal(resp, &intermediateList); err != nil {
		return IntermediateListRespBody{}, err
	}

	return intermediateList, nil
}

type ProductListRespBody struct {
	Products []Product `json:"products"`
}

type Product struct {
	NameID string `json:"name_id"`
	Name   string `json:"name"`
}

func (c *Client) GetProductList() (productList ProductListRespBody, err error) {
	resp, err := c.httpResponse(http.MethodGet, PRODUCT_ENDPOINT, nil)
	if err != nil {
		return ProductListRespBody{}, err
	}

	if err := json.Unmarshal(resp, &productList); err != nil {
		return ProductListRespBody{}, err
	}

	return productList, nil
}

type DomainListRespBody struct {
	Domains  []Domain   `json:"domains"`
	ErrorMsg []ErrorMsg `json:"errors"`
}

type Domain struct {
	ID                  int      `json:"id"`
	Name                string   `json:"name"`
	IsPendingValidation bool     `json:"is_pending_validation"`
	DcvToken            DcvToken `json:"dcv_token"`
}

type DcvToken struct {
	Token  string `json:"token"`
	Status string `json:"status"`
}

func (c *Client) GetDomainsList() (domains []Domain, err error) {
	resp, err := c.httpResponse(http.MethodGet, DOMAIN_ENDPOINT, nil)
	if err != nil {
		return []Domain{}, err
	}
	var domainList DomainListRespBody
	if err := json.Unmarshal(resp, &domainList); err != nil {
		return []Domain{}, err
	}

	if len(domainList.Domains) == 0 {
		return []Domain{}, fmt.Errorf("digicert's domain list is empty")
	}

	return domainList.Domains, nil
}

func (c *Client) GetDomainInfo(domainID int) (domain Domain, err error) {
	url := fmt.Sprintf("%s/%d?include_dcv=true&include_validation=true", DOMAIN_ENDPOINT, domainID)
	resp, err := c.httpResponse(http.MethodGet, url, nil)
	if err != nil {
		return Domain{}, err
	}

	if err := json.Unmarshal(resp, &domain); err != nil {
		return Domain{}, err
	}
	return domain, nil
}

type ErrorMsgList struct {
	ErrorMsg []ErrorMsg `json:"errors"`
}

type ErrorMsg struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *Client) CheckDomainDCV(domainID int) (err error) {
	url := fmt.Sprintf("%s/%d/dcv/validate-token", DOMAIN_ENDPOINT, domainID)

	activateDomainresp, err := c.httpResponse(http.MethodPut, url, nil)
	if err != nil {
		return err
	}

	var errMsgList ErrorMsgList
	if err := json.Unmarshal(activateDomainresp, &errMsgList); err != nil {
		return err
	}

	if len(errMsgList.ErrorMsg) != 0 {
		// DNS LOOKUP
		return fmt.Errorf(errMsgList.ErrorMsg[0].Code, ". ", errMsgList.ErrorMsg[0].Message)
	}

	return nil
}

func (c *Client) RevokeCert(certId int) (err error) {
	url := fmt.Sprintf("%s/%d/revoke", CERT_ENDPOINT, certId)
	payloadJson := []byte(`{
		"skip_approval": true
	}`)

	resp, err := c.httpResponse(http.MethodPut, url, payloadJson)
	if err != nil {
		return err
	}

	// resp length == 0, mean revoke certificate successfully
	if len(resp) != 0 {
		var errMsgList ErrorMsgList
		if err := json.Unmarshal(resp, &errMsgList); err != nil {
			return err
		}

		if len(errMsgList.ErrorMsg) != 0 {
			return fmt.Errorf(errMsgList.ErrorMsg[0].Message)
		}
	}

	return nil
}

func (c *Client) RevokeAllCert(orderId int) (err error) {
	url := fmt.Sprintf("%s/%d/revoke", ORDER_ENDPOINT, orderId)
	jsonPayload := []byte(`{
		"skip_approval": true
		}`)

	resp, err := c.httpResponse(http.MethodPut, url, jsonPayload)
	if err != nil {
		return err
	}

	// resp length == 0, mean revoke certificate successfully
	if len(resp) != 0 {
		var errMsgList ErrorMsgList
		if err := json.Unmarshal(resp, &errMsgList); err != nil {
			return err
		}

		if len(errMsgList.ErrorMsg) != 0 {
			return fmt.Errorf(errMsgList.ErrorMsg[0].Message)
		}
	}

	return nil
}

func (c *Client) CancelOrderRequest(orderId int) (err error) {
	url := fmt.Sprintf("%s/%d/status", ORDER_ENDPOINT, orderId)
	payloadJson := []byte(`{
		"status": "canceled",
		"note": "Fail validate domain."
	}`)

	ordStatusResp, err := c.httpResponse(http.MethodPut, url, payloadJson)
	if err != nil {
		return err
	}
	// Success will not return any response
	if len(ordStatusResp) != 0 {
		return err
	}

	return nil
}
