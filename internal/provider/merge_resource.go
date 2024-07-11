package provider

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &mergeResource{}
	_ resource.ResourceWithConfigure = &mergeResource{}
)

func NewMergeResource() resource.Resource {
	return &mergeResource{}
}

type mergeResource struct {
	azureCred *azcore.TokenCredential
}

type mergeResourceModel struct {
	CertPem  types.String `tfsdk:"cert_pem"`
	Name     types.String `tfsdk:"name"`
	VaultURL types.String `tfsdk:"vault_url"`
}

// Metadata returns the resource type name.
func (r *mergeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_merge"
}

// Schema defines the schema for the resource.
func (r *mergeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Complete a certificate operation by merging the signed certificate with pending version",
		Attributes: map[string]schema.Attribute{
			"cert_pem": schema.StringAttribute{
				MarkdownDescription: "Cert to merge in PEM format",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of pending cert",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"vault_url": schema.StringAttribute{
				MarkdownDescription: "URL of Azure Key Vault",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *mergeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan mergeResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	certBlock, _ := pem.Decode([]byte(plan.CertPem.ValueString()))
	if certBlock.Type != "CERTIFICATE" {
		resp.Diagnostics.AddError(
			"Decoded PEM is not a cert",
			"A cert was not found in the provided PEM",
		)
		return
	}

	certClient, err := azcertificates.NewClient(plan.VaultURL.ValueString(), *r.azureCred, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating cert client",
			"Could not create cert client, unexpected error: "+err.Error(),
		)
		return
	}

	certBase64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
	var certs = [][]byte{[]byte(certBase64)}

	certParams := azcertificates.MergeCertificateParameters{
		X509Certificates: certs,
	}
	certResp, err := certClient.MergeCertificate(ctx, plan.Name.ValueString(), certParams, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error merging cert",
			"Could not merge cert, unexpected error: "+err.Error(),
		)
		return
	}
	_ = certResp

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *mergeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *mergeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r mergeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// Configure adds the provider configured client to the resource.
func (r *mergeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	azureCred, ok := req.ProviderData.(azcore.TokenCredential)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *azcore.TokenCredential, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.azureCred = &azureCred
}
