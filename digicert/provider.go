// Copyright (c) HashiCorp, Inc.

package digicert

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the provider.Provider interface.
var _ provider.Provider = &digicertProvider{}

type digicertProvider struct {
	version string
}

type digicertProviderModel struct {
	ApiKey types.String `tfsdk:"api_key"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &digicertProvider{
			version: version,
		}
	}
}

// Metadata satisfies the provider.Provider interface for digicertProvider
func (p *digicertProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	// provider specific implementation
	resp.TypeName = "st-digicert"
	resp.Version = p.version
}

// Schema satisfies the provider.Provider interface for digicertProvider.
func (p *digicertProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Digicert is a CA provider that manage certificates.",
		Attributes: map[string]schema.Attribute{
			"api_key": schema.StringAttribute{
				MarkdownDescription: "API key for Digicert API. May also be provided via DIGICERT_API_KEY environment variable",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}

}

// Configure satisfies the provider.Provider interface for digicertProvider.
func (p *digicertProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	apiKey := os.Getenv("DIGICERT_API_KEY")

	var data digicertProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if data.ApiKey.ValueString() != "" {
		apiKey = data.ApiKey.ValueString()
	}

	if apiKey == "" {
		resp.Diagnostics.AddError(
			"Missing API Key Configuration",
			"While configuring the provider, the API Key was not found in "+
				"the DIGICERT_API_KEY environment variable or provider "+
				"configuration block api_key attribute.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	cfg := Config{
		ApiKey: apiKey,
	}

	client, err := cfg.Client()
	if err != nil {
		resp.Diagnostics.AddError("Create Digicert client Error", err.Error())
		return
	}

	resp.ResourceData = client
}

// DataSources satisfies the provider.Provider interface for digicertProvider.
func (p *digicertProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// Provider specific implementation
	}
}

// Resources satisfies the provider.Provider interface for digicertProvider.
func (p *digicertProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertificateResource,
	}
}
