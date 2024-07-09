// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure azureKVCAProvider satisfies various provider interfaces.
var _ provider.Provider = &azureKVCAProvider{}
var _ provider.ProviderWithFunctions = &azureKVCAProvider{}

// azureKVCAProvider defines the provider implementation.
type azureKVCAProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

func (p *azureKVCAProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "azurekvca"
	resp.Version = p.version
}

func (p *azureKVCAProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *azureKVCAProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// TODO make this configurable via the provider config (Can I do something stupid like consume the azure provider?)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error authenticating to Azure",
			"Could not authenticate to Azure, unexpected error: "+err.Error(),
		)
		return
	}

	resp.ResourceData = cred
}

func (p *azureKVCAProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCreateResource,
		NewMergeResource,
		NewRequestResource,
		NewSignResource,
	}
}

func (p *azureKVCAProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return nil
}

func (p *azureKVCAProvider) Functions(ctx context.Context) []func() function.Function {
	return nil
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &azureKVCAProvider{
			version: version,
		}
	}
}
