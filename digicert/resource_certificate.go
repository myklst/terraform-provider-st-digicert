// Copyright (c) HashiCorp, Inc.

package digicert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	aliclouddns "github.com/myklst/terraform-provider-st-digicert/digicert/dns/platform/alicloud/dns"
	"github.com/myklst/terraform-provider-st-digicert/digicert/dns/platform/aws/route53"
	cloudflaredns "github.com/myklst/terraform-provider-st-digicert/digicert/dns/platform/cloudflare/dns"
	digicertapi "github.com/myklst/terraform-provider-st-digicert/digicertAPI"
)

var (
	_ resource.Resource                = &CertificateResource{}
	_ resource.ResourceWithConfigure   = &CertificateResource{}
	_ resource.ResourceWithImportState = &CertificateResource{}
	_ resource.ResourceWithModifyPlan  = &CertificateResource{}
)

func NewCertificateResource() resource.Resource {
	return &CertificateResource{}
}

var (
	mutex          sync.Mutex
	used_order_ids []int
)

type CertificateResource struct {
	client *digicertapi.Client
}

type CertificateResourceModel struct {
	Sans                 types.List    `tfsdk:"sans"`
	CommonName           types.String  `tfsdk:"common_name"`
	OrganizationID       types.Int32   `tfsdk:"organization_id"`
	MinDayRemaining      types.Int32   `tfsdk:"min_days_remaining"`
	ProductName          types.String  `tfsdk:"product_name"`
	DNSChallenge         *DNSChallenge `tfsdk:"dns_challenge"`
	OrderValidityDays    types.Int32   `tfsdk:"order_validity_days"`
	CertificatePem       types.String  `tfsdk:"certificate_pem"`
	IssuerPem            types.String  `tfsdk:"issuer_pem"`
	RootPem              types.String  `tfsdk:"root_pem"`
	PrivateKeyPem        types.String  `tfsdk:"private_key_pem"`
	OrderID              types.Int32   `tfsdk:"order_id"`
	CertificateID        types.Int32   `tfsdk:"certificate_id"`
	OrderValidTill       types.String  `tfsdk:"order_valid_till"`
	CertificateValidTill types.String  `tfsdk:"certificate_valid_till"`
	Csr                  types.String  `tfsdk:"csr"`
}

type OrderPayload struct {
	Certificate      CertificatePayload `json:"certificate"`
	Organization     Organization       `json:"organization"`
	OrderValidity    ValidityPayload    `json:"order_validity,omitempty"`
	PaymentMethod    string             `json:"payment_method"`
	RenewalOfOrderID int                `json:"renewal_of_order_id"`
	DcvMethod        string             `json:"dcv_method"`
}

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

type DomainPayload struct {
	Name         string       `json:"name"`
	Organization Organization `json:"organization"`
	Validations  []Validation `json:"validations"`
	DcvMethod    string       `json:"dcv_method"`
}

type ValidityPayload struct {
	Days int `json:"days,omitempty"`
}

type OrderListRespBody struct {
	Orders   []OrderRespBody `json:"orders"`
	ErrorMsg []ErrorMsg      `json:"errors"`
}

type OrderRespBody struct {
	ID             int         `json:"id"`
	Certificate    Certificate `json:"certificate"`
	Status         string      `json:"status"`
	OrderValidTill string      `json:"order_valid_till"`
	IsRenewed      bool        `json:"is_renewed"`
	ErrorMsg       []ErrorMsg  `json:"errors"`
}

type ProductListRespBody struct {
	Products []Product `json:"products"`
}

type Product struct {
	NameID string `json:"name_id"`
	Name   string `json:"name"`
}

type IntermediateListRespBody struct {
	Intermediates []Intermediates `json:"intermediates"`
}

type Intermediates struct {
	SubjectCommonName string `json:"subject_common_name"`
	IssuerCommonName  string `json:"issuer_common_name"`
}

type Certificate struct {
	ID               int                `json:"id"`
	Status           string             `json:"status"`
	CommonName       string             `json:"common_name"`
	ValidTill        string             `json:"valid_till"`
	CertificateChain []CertificateChain `json:"certificate_chain"`
	Organization     Organization       `json:"organization"`
	Csr              string             `json:"csr"`
	PrivateKey       string             `json:"-"`
	CertificatePem   string             `json:"-"`
	IssuerPem        string             `json:"-"`
	RootPem          string             `json:"-"`
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

type DomainRespBody struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	DcvToken DcvToken `json:"dcv_token"`
}

type CertificateChainList struct {
	CertificateChain []CertificateChain `json:"intermediates"`
}

type CertificateChain struct {
	SubjectCommonName string `json:"subject_common_name"`
	Pem               string `json:"pem"`
}

type Organization struct {
	ID int `json:"id"`
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

type Validation struct {
	Type string `json:"type"`
}

type AddDomainRespBody struct {
	ID       int        `json:"id"`
	DcvToken DcvToken   `json:"dcv_token"`
	ErrorMsg []ErrorMsg `json:"errors"`
}

type DcvToken struct {
	Token  string `json:"token"`
	Status string `json:"status"`
}

type DNSChallenge struct {
	Provider types.String `tfsdk:"provider"`
	Config   types.Map    `tfsdk:"config"`
}

type ErrorMsgList struct {
	ErrorMsg []ErrorMsg `json:"errors"`
}

type ErrorMsg struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// With the resource.Resource implementation
func (r *CertificateResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *CertificateResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The st-digicert_certificate resource can be used to create " +
			"and manage an certificate in Digicert",
		Attributes: map[string]schema.Attribute{
			"common_name": schema.StringAttribute{
				Description: "Common name that request to issue certificate.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					// domain min lenght and max lenght
					stringvalidator.LengthBetween(3, 255),
				},
			},
			"sans": schema.ListAttribute{
				Description: "Additional domains to be secured. Can result in additional costs.",
				ElementType: types.StringType,
				Optional:    true,
				// Computed:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
				Validators: []validator.List{
					// domain min lenght and max lenght
					listvalidator.ValueStringsAre(stringvalidator.LengthBetween(3, 255)),
				},
			},
			"organization_id": schema.Int32Attribute{
				Description: "The Organization that is registered in Digicert." +
					"It is used to bind with the certificate when requesting certificate.",
				Required: true,
				PlanModifiers: []planmodifier.Int32{
					int32planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int32{
					int32validator.AtLeast(1),
				},
			},
			"min_days_remaining": schema.Int32Attribute{
				Description: "Threshole of the expired date remaining of the certificate.",
				Optional:    true,
				Computed:    true,
				Default:     int32default.StaticInt32(30),
				Validators: []validator.Int32{
					int32validator.Between(-1, 398),
				},
			},
			"product_name": schema.StringAttribute{
				Description: "ID of the intermediate certificate authority (ICA)" +
					"certificate to select as the issuing certificate. ",
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(4),
				},
			},
			"order_validity_days": schema.Int32Attribute{
				Description: "Validity period of the order. Number of days the order is valid.",
				Optional:    true,
				Computed:    true,
				Default:     int32default.StaticInt32(365),
				Validators: []validator.Int32{
					int32validator.Between(1, 1095),
				},
			},
			"order_id": schema.Int32Attribute{
				Description: "Order's ID.",
				Computed:    true,
			},
			"certificate_pem": schema.StringAttribute{
				Description: "The certificate in PEM format.",
				Computed:    true,
				Sensitive:   true,
			},
			"issuer_pem": schema.StringAttribute{
				Description: "The intermediate certificates of the issuer.",
				Computed:    true,
				Sensitive:   true,
			},
			"root_pem": schema.StringAttribute{
				Description: "The Root certiifacets of the issuer.",
				Computed:    true,
				Sensitive:   true,
			},
			"private_key_pem": schema.StringAttribute{
				Description: "The certificate's private key, in PEM format.",
				Computed:    true,
				Sensitive:   true,
			},
			"csr": schema.StringAttribute{
				Description: "Certificate signing request (CSR).",
				Computed:    true,
			},
			"certificate_id": schema.Int32Attribute{
				Description: "Certificate's ID.",
				Computed:    true,
			},
			"order_valid_till": schema.StringAttribute{
				Description: "The date of the order is valid until.",
				Computed:    true,
			},
			"certificate_valid_till": schema.StringAttribute{
				Description: "The date of the certicate is valid until",
				Computed:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"dns_challenge": schema.SingleNestedBlock{
				Attributes: map[string]schema.Attribute{
					"provider": schema.StringAttribute{
						Description: "DNS provider which manage the domain. " +
							"Valid provider are `route53`,`alidns`, and `cloudflare`.",
						Required: true,
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(2),
						},
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.RequiresReplace(),
						},
					},
					"config": schema.MapAttribute{
						ElementType: types.StringType,
						Description: "Configuration of the DNS provider," +
							"The valid config for route53 will be `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY`; " +
							"For `alidns`, the valid config will be `ALICLOUD_ACCESS_KEY` and `ALICLOUD_SECRET_KEY`, " +
							"For `cloudflare`, the valid config is `CLOUDFLARE_DNS_API_TOKEN` and `CLOUDFLARE_ZONE_API_TOKEN`",
						Required:  true,
						Sensitive: true,
						Validators: []validator.Map{
							mapvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(2)),
						},
						PlanModifiers: []planmodifier.Map{
							mapplanmodifier.RequiresReplace(),
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *CertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*digicertapi.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *digicertapi.Credential, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

func (r *CertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "[resourceDigicertCertificateCreate!]")
	var data CertificateResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Check if certificate for the domain already existed in Digicert
	cn := data.CommonName.ValueString()
	existedOrdId, err := r.isCommonNameExisted(cn)
	if err != nil {
		resp.Diagnostics.AddError("Check cert duplication Error.", err.Error())
		tflog.Debug(ctx, fmt.Sprintf("Error when checking the %s is existed in Digicert", cn))
		return
	}
	if existedOrdId != -1 {
		resp.Diagnostics.AddError("Duplication order placement.",
			fmt.Sprintf("%s already placed order on Digicert, order id: %d", cn, existedOrdId))
		return
	}

	// Generate CSR and private key for later used
	dnsName := []string{}
	data.Sans.ElementsAs(ctx, &dnsName, false)

	csr, privateKey, err := r.generateCSR(int(data.OrganizationID.ValueInt32()), data.CommonName.ValueString(), dnsName)
	if err != nil {
		tflog.Debug(ctx, fmt.Sprintf("Error Generate CSR Error, error: %s", err.Error()))
		resp.Diagnostics.AddError("Generate CSR Error.", err.Error())
		return
	}

	// Check if there is order can be reissued
	order, foundReissuableOrder, err := r.retrieveReissuableOrd(-1)
	if err != nil {
		tflog.Debug(ctx, fmt.Sprintf("Error Retreive reissuable's order id in Digicert, error: %s", err.Error()))
		resp.Diagnostics.AddError("Retreive reissuable's order id Error.", err.Error())
		return
	}

	var issueCert IssueCertRespBody
	if foundReissuableOrder {
		// Reissue cert
		issueCert, err = r.reissueCertificate(ctx, data, order, csr)
		if err != nil {
			tflog.Debug(ctx, fmt.Sprintf("Error Reissue certificate, error: %s", err.Error()))
			resp.Diagnostics.AddError("Reissue certificate Error.", err.Error())
			return
		}

		orderExpiredDate, _ := time.Parse("2006-01-02", order.OrderValidTill)
		orderExpiredDaysRemaining := int(time.Until(orderExpiredDate).Hours()/24) + 1
		// Update order if its' valid till days is exceed the min day remaining(set by user),
		if int(data.MinDayRemaining.ValueInt32()) > orderExpiredDaysRemaining {
			// Update Order
			// order valid remaining days add on with the new order validity days.
			orderExpiredDaysRemaining = int(data.OrderValidityDays.ValueInt32()) + orderExpiredDaysRemaining
			issueCert, err = r.renewCertificate(ctx, data, order.ID, csr, orderExpiredDaysRemaining)
			if err != nil {
				tflog.Debug(ctx, fmt.Sprintf("Error Renew certificate, error: %s", err.Error()))
				resp.Diagnostics.AddError("Renew certificate Error.", err.Error())
				return
			}
		}
	} else {
		// Issue cert
		issueCert, err = r.issueCertificate(ctx, data, csr)
		if err != nil {
			tflog.Debug(ctx, fmt.Sprintf("Error Issue certificate, error: %s", err.Error()))
			resp.Diagnostics.AddError("Issue certificate Error.", err.Error())
			return
		}
	}

	ord, err := r.getOrderInfo(issueCert.OrderID)
	if err != nil {
		resp.Diagnostics.AddError("Get Order Info Error.", err.Error())
		return
	}

	// DNS Challenge
	dnsCreds := make(map[string]types.String, len(data.DNSChallenge.Config.Elements()))
	diags := data.DNSChallenge.Config.ElementsAs(context.Background(), &dnsCreds, false)
	if diags.HasError() {
		return
	}

	if challengeErr := r.dnsChallenge(data.DNSChallenge.Provider.ValueString(), dnsCreds, issueCert); challengeErr != nil {
		// if the domain is still valid but fail dns challenge, (validated domain before but redo dns challenge)
		// it will still able to place order, even the dns challenge is fail.
		if ord.Status == "pending" {
			resp.Diagnostics.AddError("DNS Challange Error.", challengeErr.Error())
			if err := r.cancelOrderRequest(ord.ID); err != nil {
				resp.Diagnostics.AddError("Unable to cancel order request, "+
					"cancel the order manually on Web Console is required"+
					"before continue using terraform to manage Digicert resource. "+
					fmt.Sprintf("Order id: %d", ord.ID), err.Error())
				return
			}
		} else {
			resp.Diagnostics.AddWarning("DNS Challange fail, but the cert is still issued since the domain is still valid to use.", challengeErr.Error())
		}
	}

	certChain, err := r.getCertificateChain(issueCert.CertificateID)
	if err != nil {
		resp.Diagnostics.AddError("Get Certificate Chain Error.", err.Error())
		return
	}

	certPem, issuerPem, rootPem, err := r.distinguishCertType(certChain, data.CommonName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Fail to get intermediate list Error.", err.Error())
		return
	}

	data.CertificatePem = types.StringValue(certPem)
	data.IssuerPem = types.StringValue(issuerPem)
	data.RootPem = types.StringValue(rootPem)

	data.OrderID = types.Int32Value(int32(ord.ID))
	data.CertificateID = types.Int32Value(int32(ord.Certificate.ID))
	data.PrivateKeyPem = types.StringValue(privateKey)
	data.OrderValidTill = types.StringValue(ord.OrderValidTill)
	data.CertificateValidTill = types.StringValue(ord.Certificate.ValidTill)
	data.Csr = types.StringValue(csr)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CertificateResource) cancelOrderRequest(orderID int) error {
	// Cancel the order request
	payloadJson := []byte(`{
			"status": "canceled",
			"note": "Fail validate domain."
		}`)

	ordStatusResp, err := r.client.UpdateOrderStatus(orderID, payloadJson)
	if err != nil {
		return err
	}
	// Success will not return any response
	if len(ordStatusResp) != 0 {
		return err
	}

	return nil
}

func (r *CertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state CertificateResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)

	// Get from digicert database
	// use common name to do query
	orders, err := r.getOrders(state.CommonName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Get Order Info Error.", err.Error())
		return
	}

	// Order not found
	if len(orders.Orders) == 0 {
		resp.Diagnostics.AddError("Retrieve order Error", "Unable to find the order using the common name, "+
			"Certificate might been destroy outside terraform.")
		return
	}

	var orderRes OrderRespBody
	for _, order := range orders.Orders {
		if order.Certificate.Status == "issued" || order.Certificate.Status == "" {
			orderRes = order
			break
		}
	}

	state.OrderID = types.Int32Value(int32(orderRes.ID))
	state.CertificateID = types.Int32Value(int32(orderRes.Certificate.ID))
	state.CommonName = types.StringValue(orderRes.Certificate.CommonName)
	// state = all the return

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

}

// Update the resource and sets the updated Terraform state on success.
func (r *CertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "[resourceDigicertCertificateUpdate!]")
	// Retrieve values from plan
	var plan CertificateResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state CertificateResourceModel
	diags = resp.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	expired, err := r.certificateHasExpired(int(plan.MinDayRemaining.ValueInt32()), state.CertificateValidTill.ValueString())
	if err != nil {
		return
	}

	// if cert is not expired, update only the changed of user inputs.
	if !expired {
		state.OrderValidityDays = plan.OrderValidityDays

		setStateDiags := resp.State.Set(ctx, state)
		resp.Diagnostics.Append(setStateDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		return
	}

	// Revoke cert
	if err := r.revokeCertificate(int(state.CertificateID.ValueInt32())); err != nil {
		resp.Diagnostics.AddError("Revoke order error.",
			fmt.Sprintf("Error while revoking certificate for '%s', order id: %d, error: %s", state.CommonName, state.OrderID.ValueInt32(), err.Error()))
		return
	}

	// Issue or Renew for a new cert
	// Generate a new csr, and the private key
	dnsName := []string{}
	plan.Sans.ElementsAs(ctx, &dnsName, false)

	csr, privateKey, err := r.generateCSR(int(plan.OrganizationID.ValueInt32()), plan.CommonName.ValueString(), dnsName)
	if err != nil {
		resp.Diagnostics.AddError("Generate CSR Error", err.Error())
		return
	}

	// Get the order's expired date in state
	orderExpiredDate, err := time.Parse("2006-01-02", state.OrderValidTill.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Time Parse Error", err.Error())
		return
	}

	orderValidTillDays := int(time.Until(orderExpiredDate).Hours()/24) + 1

	var issueCert IssueCertRespBody
	// Check if the order in state is hiting the min expired remaining days' threshold.
	if orderValidTillDays > int(plan.MinDayRemaining.ValueInt32()) {
		// Reissue cert to the order ID.
		order := OrderRespBody{
			ID:             int(state.OrderID.ValueInt32()),
			OrderValidTill: state.OrderValidTill.ValueString(),
		}

		issueCert, err = r.reissueCertificate(ctx, plan, order, csr)
		if err != nil {
			resp.Diagnostics.AddError("Reissue Certificate Error", err.Error())
			return
		}
	} else {
		// Try reissue to other order.
		order, isOrdReissuable, err := r.retrieveReissuableOrd(int(plan.MinDayRemaining.ValueInt32()))
		if err != nil {
			resp.Diagnostics.AddError("Retreive Reissuable Order Id Error", err.Error())
			return
		}

		if isOrdReissuable {
			// Reissue cert
			issueCert, err = r.reissueCertificate(ctx, plan, order, csr)
			if err != nil {
				resp.Diagnostics.AddError("Reissue Certificate Error", err.Error())
				return
			}
		} else {
			// Renew order
			// Order valid remaining validityDays add with the new expiry validityDays and the remaining expiry validityDays.
			orderValidTillDays = int(plan.OrderValidityDays.ValueInt32()) + orderValidTillDays
			issueCert, err = r.renewCertificate(ctx, plan, int(state.OrderID.ValueInt32()), csr, orderValidTillDays)
			if err != nil {
				resp.Diagnostics.AddError("Renew Certificate Error", err.Error())
				return
			}

		}
	}

	ord, err := r.getOrderInfo(issueCert.OrderID)
	if err != nil {
		resp.Diagnostics.AddError("Get Order Info Error", err.Error())
		return
	}

	// DNS Challenge
	dnsCreds := make(map[string]types.String, len(plan.DNSChallenge.Config.Elements()))
	diags = plan.DNSChallenge.Config.ElementsAs(context.Background(), &dnsCreds, false)
	if diags.HasError() {
		return
	}

	if challengeErr := r.dnsChallenge(plan.DNSChallenge.Provider.ValueString(), dnsCreds, issueCert); challengeErr != nil {
		// if the domain is still valid but fail dns challenge, (validated domain before but redo dns challenge)
		// it will still able to place order, even the dns challenge is fail.
		if ord.Certificate.Status == "pending" {
			resp.Diagnostics.AddError("DNS Challange Error.", challengeErr.Error())
			if err := r.cancelOrderRequest(ord.ID); err != nil {
				resp.Diagnostics.AddError("Unable to cancel order request, "+
					"cancel the order manually on Web Console is required"+
					"before continue using terraform to manage Digicert resource. "+
					fmt.Sprintf("Order id: %d", ord.ID), err.Error())
			}
		} else {
			resp.Diagnostics.AddWarning("DNS Challange fail, but the cert is still issued since the domain is still valid to use.", challengeErr.Error())
		}

		return
	}

	certChain, err := r.getCertificateChain(issueCert.CertificateID)
	if err != nil {
		resp.Diagnostics.AddError("Get Certificate Chain Error.", err.Error())
		return
	}

	certPem, issuerPem, rootPem, err := r.distinguishCertType(certChain, plan.CommonName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Retrieve cert pem Error.", err.Error())
		return
	}

	plan.CertificatePem = types.StringValue(certPem)
	plan.IssuerPem = types.StringValue(issuerPem)
	plan.RootPem = types.StringValue(rootPem)

	plan.OrderID = types.Int32Value(int32(ord.ID))
	plan.CertificateID = types.Int32Value(int32(ord.Certificate.ID))
	plan.PrivateKeyPem = types.StringValue(privateKey)
	plan.OrderValidTill = types.StringValue(ord.OrderValidTill)
	plan.CertificateValidTill = types.StringValue(ord.Certificate.ValidTill)
	plan.Csr = types.StringValue(csr)

	setStateDiags := resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(setStateDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *CertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Info(ctx, "[resourceDigicertCertificateDelete!]")
	// Retrieve values from state
	var state CertificateResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)

	if err := r.revokeCertificate(int(state.CertificateID.ValueInt32())); err != nil {
		resp.Diagnostics.AddError("Revoke order error.",
			fmt.Sprintf("Error while revoking certificate for '%s', order id: %d, error: %s", state.CommonName, state.OrderID.ValueInt32(), err.Error()))
	}

	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *CertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("common_name"), req.ID)...)
}

func (r *CertificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If not being Destroy
	if !req.Plan.Raw.IsNull() {
		var plan CertificateResourceModel
		diags := req.Plan.Get(ctx, &plan)
		resp.Diagnostics.Append(diags...)
		// Validation of dns_challenge
		provider := plan.DNSChallenge.Provider.ValueString()
		creds := make(map[string]types.String, len(plan.DNSChallenge.Config.Elements()))
		diags = plan.DNSChallenge.Config.ElementsAs(context.Background(), &creds, false)

		if diags.HasError() {
			diags.AddError("Access Map Value Error.", "Unable to obtain map value.")
			return
		}

		for k := range creds {
			switch strings.ToLower(provider) {
			case "route53":
				if k != "AWS_ACCESS_KEY_ID" && k != "AWS_SECRET_ACCESS_KEY" && k != "AWS_REGION" {
					resp.Diagnostics.AddAttributeError(path.Root("dns_challenge"), "DNS Configure Error.",
						"Config only allow AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION, "+
							fmt.Sprintf("But now has %s", k))
					return
				}
			case "alidns":
				if k != "ALICLOUD_ACCESS_KEY" && k != "ALICLOUD_SECRET_KEY" {
					resp.Diagnostics.AddAttributeError(path.Root("dns_challenge"), "DNS Configure Error.",
						"Config only allow ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY, "+
							fmt.Sprintf("But now has %s", k))
					return
				}
			case "cloudflare":
				if k != "CLOUDFLARE_DNS_API_TOKEN" && k != "CLOUDFLARE_ZONE_API_TOKEN" {
					resp.Diagnostics.AddAttributeError(path.Root("dns_challenge"), "DNS Configure Error.",
						"Config only allow CLOUDFLARE_DNS_API_TOKEN and CLOUDFLARE_ZONE_API_TOKEN , "+
							fmt.Sprintf("But now has %s", k))
					return
				}
			default:
				resp.Diagnostics.AddAttributeError(path.Root("dns_challenge"), "Invalid DNS Provider.", "Provider Not found.")
				return
			}
		}
	}

	// if not being create and destroy
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var plan CertificateResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)

	expired, err := r.certificateHasExpired(int(plan.MinDayRemaining.ValueInt32()), plan.CertificateValidTill.ValueString())
	if err != nil {
		return
	}

	if expired {
		// trigger update
		setPrvKey := resp.Plan.SetAttribute(ctx, path.Root("private_key_pem"), types.StringUnknown())
		setCert := resp.Plan.SetAttribute(ctx, path.Root("certificate_pem"), types.StringUnknown())
		setIssuerPem := resp.Plan.SetAttribute(ctx, path.Root("issuer_pem"), types.StringUnknown())
		setRootPem := resp.Plan.SetAttribute(ctx, path.Root("root_pem"), types.StringUnknown())
		setCsr := resp.Plan.SetAttribute(ctx, path.Root("csr"), types.StringUnknown())
		setOrderId := resp.Plan.SetAttribute(ctx, path.Root("order_id"), types.Int32Unknown())
		setCertId := resp.Plan.SetAttribute(ctx, path.Root("certificate_id"), types.Int32Unknown())
		setOrderValidTill := resp.Plan.SetAttribute(ctx, path.Root("order_valid_till"), types.StringUnknown())
		setCertValidTill := resp.Plan.SetAttribute(ctx, path.Root("certificate_valid_till"), types.StringUnknown())

		resp.Diagnostics.Append(setPrvKey...)
		resp.Diagnostics.Append(setCert...)
		resp.Diagnostics.Append(setIssuerPem...)
		resp.Diagnostics.Append(setRootPem...)
		resp.Diagnostics.Append(setCsr...)
		resp.Diagnostics.Append(setOrderId...)
		resp.Diagnostics.Append(setCertId...)
		resp.Diagnostics.Append(setOrderValidTill...)
		resp.Diagnostics.Append(setCertValidTill...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
}

func (r *CertificateResource) certificateHasExpired(minDaysRemaining int, certValidTill string) (bool, error) {
	certValidTillDate, err := time.Parse("2006-01-02", certValidTill)
	if err != nil {
		return false, err
	}

	certRemainingDays := time.Until(certValidTillDate).Hours()/24 + 1

	if int(minDaysRemaining) >= int(certRemainingDays) {
		return true, nil
	}

	return false, nil
}

func (r *CertificateResource) issueCertificate(ctx context.Context, data CertificateResourceModel, csr string) (issueCert IssueCertRespBody, err error) {
	dnsName := []string{}
	data.Sans.ElementsAs(ctx, &dnsName, false)

	product, err := r.getProductInfo(data.ProductName.ValueString())
	if err != nil {
		return issueCert, err
	}

	// if user didn't input day
	payload := OrderPayload{
		Certificate: CertificatePayload{
			CommonName:    data.CommonName.ValueString(),
			DNSNames:      dnsName,
			CSR:           csr,
			SignatureHash: "sha256",
			CACertID:      product.NameID,
		},
		Organization: Organization{
			ID: int(data.OrganizationID.ValueInt32()),
		},
		OrderValidity: ValidityPayload{
			Days: int(data.OrderValidityDays.ValueInt32()),
		},
		PaymentMethod: "balance",
		DcvMethod:     "dns-txt-token",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return issueCert, err
	}

	resp, err := r.client.IssueCert(jsonPayload, product.NameID)
	if err != nil {
		return issueCert, err
	}

	if err := json.Unmarshal(resp, &issueCert); err != nil {
		return issueCert, err
	}

	if len(issueCert.ErrorMsg) != 0 {
		return issueCert, fmt.Errorf("error issue certificate, error: %s", fmt.Sprintf("%s. %s",
			issueCert.ErrorMsg[0].Code, issueCert.ErrorMsg[0].Message))
	}

	return issueCert, nil
}

func (r *CertificateResource) reissueCertificate(ctx context.Context, data CertificateResourceModel, order OrderRespBody, csr string) (issueCert IssueCertRespBody, err error) {
	dnsName := []string{}
	data.Sans.ElementsAs(ctx, &dnsName, false)

	product, err := r.getProductInfo(data.ProductName.ValueString())
	if err != nil {
		return issueCert, err
	}

	payload := OrderPayload{
		Certificate: CertificatePayload{
			CommonName:    data.CommonName.ValueString(),
			DNSNames:      dnsName,
			CSR:           csr,
			SignatureHash: "sha256",
			CACertID:      product.NameID,
		},
		DcvMethod: "dns-txt-token",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return issueCert, err
	}

	// check is the  common name is duplicated
	cn := data.CommonName.ValueString()
	existedOrdId, err := r.isCommonNameExisted(cn)
	if err != nil {
		return issueCert, fmt.Errorf("check duplication Error. %s", err.Error())
	}
	if existedOrdId != -1 {
		return issueCert, fmt.Errorf("duplication order placement. %s already placed order in Digicert, order id: %d", cn, existedOrdId)
	}

	var resp []byte
	// Reissue Cert
	resp, err = r.client.ReissueCert(order.ID, jsonPayload)
	if err != nil {
		return issueCert, err
	}

	if err = json.Unmarshal(resp, &issueCert); err != nil {
		return issueCert, err
	}

	if len(issueCert.ErrorMsg) != 0 {
		return issueCert, fmt.Errorf("error reissue certificate, error: %s", fmt.Sprintf("%s. %s",
			issueCert.ErrorMsg[0].Code, issueCert.ErrorMsg[0].Message))
	}

	return issueCert, nil
}

func (r *CertificateResource) renewCertificate(ctx context.Context, data CertificateResourceModel, orderId int, csr string, orderValidDays int) (renewCert IssueCertRespBody, err error) {
	dnsName := []string{}
	data.Sans.ElementsAs(ctx, &dnsName, false)

	product, err := r.getProductInfo(data.ProductName.ValueString())
	if err != nil {
		return renewCert, err
	}

	payload := OrderPayload{
		Certificate: CertificatePayload{
			CommonName:    data.CommonName.ValueString(),
			DNSNames:      dnsName,
			CSR:           csr,
			SignatureHash: "sha256",
			CACertID:      product.NameID,
		},
		Organization: Organization{
			ID: int(data.OrganizationID.ValueInt32()),
		},
		OrderValidity: ValidityPayload{
			Days: orderValidDays,
		},
		RenewalOfOrderID: orderId,
		PaymentMethod:    "balance",
		DcvMethod:        "dns-txt-token",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return renewCert, err
	}

	// Renew cert use the same API ENDPOINT with issue, payload's value will
	// determine the action is renew or issue. ("RenewalOfOrderId")
	resp, err := r.client.IssueCert(jsonPayload, product.NameID)
	if err != nil {
		return renewCert, err
	}

	if err = json.Unmarshal(resp, &renewCert); err != nil {
		return renewCert, err
	}

	if len(renewCert.ErrorMsg) != 0 {
		return renewCert, fmt.Errorf("error reissue certificate, error: %s", fmt.Sprintf("%s. %s",
			renewCert.ErrorMsg[0].Code, renewCert.ErrorMsg[0].Message))
	}

	return renewCert, nil
}

func (r *CertificateResource) revokeCertificate(certID int) error {
	payloadJson := []byte(`{
		"skip_approval": true
	}`)

	resp, err := r.client.RevokeCert(certID, payloadJson)
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

func (r *CertificateResource) isCommonNameExisted(common_name string) (orderId int, err error) {
	orders, err := r.getOrders(common_name)
	if err != nil {
		return -1, err
	}

	for _, ord := range orders.Orders {
		resp, err := r.client.GetOrderInfo(ord.ID)
		if err != nil {
			return -1, err
		}

		var order OrderRespBody
		if err := json.Unmarshal(resp, &order); err != nil {
			return -1, err
		}

		// If the certificate hasn't been revoked/reissued, API will not return the certificate's status.
		// Cert Status: issued == "", reissued == "issued", revoked == "revoked"
		if !order.IsRenewed && (order.Certificate.Status == "issued" || order.Certificate.Status == "") {
			return order.ID, nil
		}
	}

	// Not found
	return -1, nil
}

// Filter: order_status == 'issued', sequence: latest
func (r *CertificateResource) getOrders(commonName string) (orders OrderListRespBody, err error) {
	resp, err := r.client.GetOrders(commonName)
	if err != nil {
		return orders, err
	}

	if err := json.Unmarshal(resp, &orders); err != nil {
		return orders, err
	}

	// check if any error msg return from API
	for _, errormsg := range orders.ErrorMsg {
		return orders, errors.New(errormsg.Message)
	}

	// API result will only return with the primary certificate,
	// Therefore, filter the common name that is same as the primary domain name.
	if commonName != "" {
		var filteredOrds OrderListRespBody
		for _, ord := range orders.Orders {
			if commonName == ord.Certificate.CommonName {
				filteredOrds.Orders = append(filteredOrds.Orders, ord)
			}
		}
		return filteredOrds, nil
	}

	return orders, nil
}

func (r *CertificateResource) getOrderInfo(orderId int) (order OrderRespBody, err error) {
	resp, err := r.client.GetOrderInfo(orderId)
	if err != nil {
		return order, err
	}

	if err := json.Unmarshal(resp, &order); err != nil {
		return order, err
	}

	return order, nil
}

func (r *CertificateResource) getProductInfo(productName string) (product Product, err error) {
	resp, err := r.client.GetProductList()
	if err != nil {
		return product, err
	}

	var productList ProductListRespBody
	if err := json.Unmarshal(resp, &productList); err != nil {
		return product, err
	}

	for _, product := range productList.Products {
		if strings.EqualFold(product.Name, productName) {
			return product, nil
		}

	}

	return product, fmt.Errorf("API Key Name is not found in Digicert System. " +
		"Please double-check that the API key name exists in the Digicert system")
}

func (r *CertificateResource) getIntermediateList() (intermediateList IntermediateListRespBody, err error) {
	resp, err := r.client.GetIntermediateList()
	if err != nil {
		return intermediateList, err
	}

	if err := json.Unmarshal(resp, &intermediateList); err != nil {
		return intermediateList, err
	}

	return intermediateList, nil
}

func (r *CertificateResource) getCertificateChain(certID int) (certificateChains []CertificateChain, err error) {
	resp, err := r.client.GetCertificateChain(certID)
	if err != nil {
		return certificateChains, err
	}

	var certificateChainList CertificateChainList
	if err := json.Unmarshal(resp, &certificateChainList); err != nil {
		return certificateChains, err
	}

	return certificateChainList.CertificateChain, nil
}

func (r *CertificateResource) getAllDomains() (domains []Domain, err error) {
	resp, err := r.client.GetDomainsList()
	if err != nil {
		return domains, err
	}
	var domainList DomainListRespBody
	if err := json.Unmarshal(resp, &domainList); err != nil {
		return domains, err
	}

	if len(domainList.Domains) == 0 {
		return domains, fmt.Errorf("digicert's domain list is empty")
	}
	return domainList.Domains, nil
}

func (r *CertificateResource) retrieveReissuableOrd(minOrderRemainingDays int) (order OrderRespBody, isOrdReissuable bool, err error) {
	orders, err := r.getOrders("")
	if err != nil {
		return order, false, err
	}

	for _, ord := range orders.Orders {
		// retrieve the certificate info
		resp, err := r.client.GetOrderInfo(ord.ID)
		if err != nil {
			return order, false, err
		}

		var order OrderRespBody
		if err := json.Unmarshal(resp, &order); err != nil {
			return order, false, err
		}

		orderExpiredDate, err := time.Parse("2006-01-02", ord.OrderValidTill)
		if err != nil {
			return order, false, fmt.Errorf("time Parse Error %s", err.Error())
		}
		orderExpiredDaysRemaining := int(((orderExpiredDate.Unix() - time.Now().Unix()) / (24 * 3600))) + 1

		// retrieve one order id if its certifcate status = "revoked"
		if order.Certificate.Status == "revoked" && !order.IsRenewed && orderExpiredDaysRemaining > minOrderRemainingDays {
			// check if the order id is grab by others threat (tf's concurrent)
			if isAbleToUseOrderId(order.ID) {
				return order, true, nil
			}
		}
	}

	// Unable to reissue, empty the struct.
	order = OrderRespBody{}
	return order, false, nil
}

func (r *CertificateResource) generateCSR(orgID int, commonName string, sans []string) (csr string, privateKeyPem string, err error) {
	body, err := r.client.GetOrgInfoByID(orgID)
	if err != nil {
		return "", "", err
	}

	var org Organization
	if err := json.Unmarshal(body, &org); err != nil {
		return "", "", err
	}

	// Generate Private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyPEM := pem.EncodeToMemory(privateKeyBlock)
	privateKeyString := string(privateKeyPEM)

	// Create Certificate Cert request
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: sans,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return "", "", err
	}

	csrBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}
	csrPEM := pem.EncodeToMemory(csrBlock)

	return string(csrPEM), privateKeyString, nil
}

const (
	DELETE_RECORD = "DELETE"
	UPSERT_RECORD = "UPSERT"
)

func (r *CertificateResource) dnsChallenge(dnsProvider string, dnsCreds map[string]basetypes.StringValue, order IssueCertRespBody) error {
	// Reissue action
	// - Will not return domains object from response.
	// - If the domain is valid to use, "DcvRandomValue" will not be returned.
	if len(order.Domains) == 0 && order.DcvRandomValue != "" {
		// Obatain the domain id that need to perform dns challenge
		domains, err := r.getAllDomains()
		if err != nil {
			return err
		}

		for _, domain := range domains {
			resp, err := r.client.GetDomainInfo(domain.ID)
			if err != nil {
				return err
			}

			var domainRespBody Domain
			if err := json.Unmarshal(resp, &domainRespBody); err != nil {
				return err
			}

			if domainRespBody.DcvToken.Token == order.DcvRandomValue {
				order.Domains = append(order.Domains, DomainRespBody{
					ID: domain.ID,
				})
				break
			}
		}
	}

	for _, domain := range order.Domains {
		domainResp, err := r.client.GetDomainInfo(domain.ID)
		if err != nil {
			return err
		}

		var domainRespBody Domain
		if err := json.Unmarshal(domainResp, &domainRespBody); err != nil {
			return err
		}

		if domainRespBody.IsPendingValidation {
			// Add txt record to DNS provider.
			var accessKey string
			var secretAccessKey string
			switch dnsProvider {
			case "route53":
				for k, v := range dnsCreds {
					if k == "AWS_ACCESS_KEY_ID" {
						accessKey = v.ValueString()

					}
					if k == "AWS_SECRET_ACCESS_KEY" {
						secretAccessKey = v.ValueString()
					}
				}

				route53Client, err := route53.NewClient(accessKey, secretAccessKey)
				if err != nil {
					return err
				}

				hostedZoneIds, err := route53Client.GetHostedZoneByDomainName(domainRespBody.Name)
				if err != nil {
					return err
				}

				if err := route53Client.ModifyAWSRoute53Record(UPSERT_RECORD, domainRespBody.Name, domainRespBody.DcvToken.Token, hostedZoneIds); err != nil {
					return err
				}

				defer route53Client.ModifyAWSRoute53Record(DELETE_RECORD, domainRespBody.Name, domainRespBody.DcvToken.Token, hostedZoneIds)

			case "alidns":
				for k, v := range dnsCreds {
					if k == "ALICLOUD_ACCESS_KEY" {
						accessKey = v.ValueString()

					}
					if k == "ALICLOUD_SECRET_KEY" {
						secretAccessKey = v.ValueString()
					}
				}

				alidnsClient, err := aliclouddns.NewClient(accessKey, secretAccessKey)
				if err != nil {
					return err
				}

				recordID, err := alidnsClient.CreateAliDNSRecord(domainRespBody.Name, domainRespBody.DcvToken.Token)
				if err != nil {
					return err
				}
				defer alidnsClient.DeleteDnsRecord(recordID)

			case "cloudflare":
				var token string
				for k, v := range dnsCreds {
					if k == "CLOUDFLARE_DNS_API_TOKEN" || k == "CLOUDFLARE_ZONE_API_TOKEN" {
						token = v.ValueString()
					}
				}

				cloudflareClient, err := cloudflaredns.NewClient(token)
				if err != nil {
					return err
				}

				dnsRecordID, err := cloudflareClient.UpdateRecord(domainRespBody.Name, domainRespBody.DcvToken.Token)
				if err != nil {
					return err
				}
				defer cloudflareClient.DeleteDnsRecord(dnsRecordID, domainRespBody.Name)
			}

			// Trigger validate domain action on Digicert
			checkDomain := func() error {
				activateDomainresp, err := r.client.CheckDomainDCV(domainRespBody.ID)
				if err != nil {
					return backoff.Permanent(err)
				}

				var errMsgList ErrorMsgList
				if err := json.Unmarshal(activateDomainresp, &errMsgList); err != nil {
					return backoff.Permanent(err)
				}

				if len(errMsgList.ErrorMsg) != 0 {
					// DNS LOOKUP
					if errMsgList.ErrorMsg[0].Code == "invalid_dns_txt" {
						return fmt.Errorf("error digicert validate domain, error: %s", errMsgList.ErrorMsg[0].Message)
					}
					return backoff.Permanent(err)
				}
				return nil
			}

			// DNS Cached, Retry for 6 minutes
			if err = retryOperator(checkDomain, 6*time.Minute); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *CertificateResource) distinguishCertType(certificateChain []CertificateChain, cn string) (certPem string, issuerPem string, rootPem string, err error) {
	intermediateList, err := r.getIntermediateList()
	if err != nil {
		return "", "", "", err
	}

	// Store cert value
	for _, cert := range certificateChain {
		// Certiifcate pem
		if cert.SubjectCommonName == cn {
			certPem = cert.Pem
		}
		// Unable to retrieve the intermediates of the cert from any api
		// Therefore, list all the intermediates and compare with the
		// name from the certificate chain list.
		for _, intermediate := range intermediateList.Intermediates {
			if intermediate.SubjectCommonName == cert.SubjectCommonName {
				// issuer pem
				issuerPem = cert.Pem
			}
		}

		// the last one must be the root certificate
		rootPem = cert.Pem
	}
	return certPem, issuerPem, rootPem, nil
}

func isAbleToUseOrderId(orderID int) bool {
	mutex.Lock()
	defer mutex.Unlock()

	// check if the order id is grab by others threat (tf's concurrent)
	for _, order_id := range used_order_ids {
		if order_id == orderID {
			return false
		}
	}

	used_order_ids = append(used_order_ids, orderID)
	return true
}

// Acceptance Test use only
func (r *CertificateResource) revokedAllOrders() error {
	resp, err := r.client.GetOrdersList()
	if err != nil {
		return err
	}
	var orders OrderListRespBody
	if err := json.Unmarshal(resp, &orders); err != nil {
		return err
	}

	for _, errormsg := range orders.ErrorMsg {
		log.Println(strings.Contains(errormsg.Code, "Missing authentication"))
	}
	var order_ids []int

	for _, order := range orders.Orders {
		order_ids = append(order_ids, order.ID)
	}

	if len(order_ids) == 0 {
		log.Println("No order issued.")
	} else {
		log.Println("Order Id is : ", order_ids)
	}

	for _, o_id := range order_ids {

		jsonData := []byte(`{
			"skip_approval": true
			}`)
		r.client.RevokeAllCert(o_id, jsonData)
	}
	return nil
}

func retryOperator(function func() error, DefaultMaxElapsedTime time.Duration) error {
	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = DefaultMaxElapsedTime
	return backoff.Retry(function, reconnectBackoff)
}
