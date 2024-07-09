package provider

import (
	"context"
	"encoding/pem"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &createResource{}
	_ resource.ResourceWithConfigure = &createResource{}
)

func NewCreateResource() resource.Resource {
	return &createResource{}
}

type createResource struct {
	azureCred *azcore.TokenCredential
}

type createKey struct {
	Curve      types.String `tfsdk:"curve"`
	Exportable types.Bool   `tfsdk:"exportable"`
	KeySize    types.Int64  `tfsdk:"key_size"`
	KeyType    types.String `tfsdk:"key_type"`
	ReuseKey   types.Bool   `tfsdk:"reuse_key"`
}

type createResourceModel struct {
	CSRPEM   types.String `tfsdk:"csr_pem"`
	Key      createKey    `tfsdk:"key"`
	Name     types.String `tfsdk:"name"`
	VaultURL types.String `tfsdk:"vault_url"`
}

// Metadata returns the resource type name.
func (r *createResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_create"
}

// Schema defines the schema for the resource.
func (r *createResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"csr_pem": schema.StringAttribute{
				Computed: true,
			},
			"key": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"curve": schema.StringAttribute{
						Optional: true,
					},
					"exportable": schema.BoolAttribute{
						Required: true,
					},
					"key_size": schema.Int64Attribute{
						Optional: true,
					},
					"key_type": schema.StringAttribute{
						Required: true,
					},
					"reuse_key": schema.BoolAttribute{
						Required: true,
					},
				},
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"vault_url": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *createResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan createResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
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

	keySize := int32(plan.Key.KeySize.ValueInt64())
	issuer := "Unknown"
	contentType := "application/x-pem-file"
	subject := "cn=" + plan.Name.ValueString()
	certParams := azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			IssuerParameters: &azcertificates.IssuerParameters{
				Name: &issuer,
			},
			KeyProperties: &azcertificates.KeyProperties{
				Curve:      (*azcertificates.CurveName)(plan.Key.Curve.ValueStringPointer()),
				Exportable: plan.Key.Exportable.ValueBoolPointer(),
				KeySize:    &keySize,
				KeyType:    (*azcertificates.KeyType)(plan.Key.KeyType.ValueStringPointer()),
				ReuseKey:   plan.Key.ReuseKey.ValueBoolPointer(),
			},
			SecretProperties: &azcertificates.SecretProperties{
				ContentType: &contentType,
			},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{
				Subject: &subject,
			},
		},
	}
	certResp, err := certClient.CreateCertificate(ctx, plan.Name.ValueString(), certParams, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating cert",
			"Could not create cert, unexpected error: "+err.Error(),
		)
		return
	}

	csrPem := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: certResp.CSR,
	}
	plan.CSRPEM = types.StringValue(string(pem.EncodeToMemory(&csrPem)))

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *createResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *createResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *createResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var state createResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	certClient, err := azcertificates.NewClient(state.VaultURL.ValueString(), *r.azureCred, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating cert client",
			"Could not create cert client, unexpected error: "+err.Error(),
		)
		return
	}

	certClient.DeleteCertificateOperation(ctx, state.Name.ValueString(), nil)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Configure adds the provider configured client to the resource.
func (r *createResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
