package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &signResource{}
	_ resource.ResourceWithConfigure = &signResource{}
)

func NewSignResource() resource.Resource {
	return &signResource{}
}

type signResource struct {
	azureCred *azcore.TokenCredential
}

type signResourceModel struct {
	CAName             types.String `tfsdk:"ca_name"`
	CSRPEM             types.String `tfsdk:"csr_pem"`
	SignatureAlgorithm types.String `tfsdk:"signature_algorithm"`
	SignedCertPEM      types.String `tfsdk:"signed_cert_pem"`
	ValidityDays       types.Int64  `tfsdk:"validity_days"`
	VaultURL           types.String `tfsdk:"vault_url"`
}

// Metadata returns the resource type name.
func (r *signResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sign"
}

// Schema defines the schema for the resource.
func (r *signResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Sign a CSR using a CA certificate in Key Vault. This can be done with CAs with non exportable keys",
		Attributes: map[string]schema.Attribute{
			"ca_name": schema.StringAttribute{
				MarkdownDescription: "Name of cert to use as the CA",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"csr_pem": schema.StringAttribute{
				MarkdownDescription: "Input CSR in PEM format",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"signature_algorithm": schema.StringAttribute{
				MarkdownDescription: "Algorithm to use when signing the cert" +
					"If the CA cert has a RSA key use one of" +
					"RS256, RS384, RS512" +
					"If the CA cert has an EC key use one of" +
					"ES256, ES384, ES512",
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"signed_cert_pem": schema.StringAttribute{
				MarkdownDescription: "Resulting signed cert in PEM format",
				Computed:            true,
			},
			"validity_days": schema.Int64Attribute{
				MarkdownDescription: "Number of days to make cert valid for",
				Required:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
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
func (r *signResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan signResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	csrBlock, _ := pem.Decode([]byte(plan.CSRPEM.ValueString()))
	if csrBlock.Type != "CERTIFICATE REQUEST" {
		resp.Diagnostics.AddError(
			"Decoded PEM is not a CSR",
			"A CSR was not found in the provided PEM",
		)
		return
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error decoding CSR",
			"Could not decode CSR, unexpected error: "+err.Error(),
		)
		return
	}

	sanIdx := slices.IndexFunc(csr.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidExtensionSubjectAltName) })
	if sanIdx < 0 {
		resp.Diagnostics.AddError(
			"Error finding SAN extension in CSR",
			"Could not find SAN extension in CSR",
		)
		return
	}
	validityHours, err := time.ParseDuration(fmt.Sprintf("%d", plan.ValidityDays.ValueInt64()*24) + "h")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error calculating validity duration",
			"Could not calculate validity validation, unexpected error: "+err.Error(),
		)
		return
	}
	template := &x509.Certificate{
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{csr.Extensions[sanIdx]},
		IsCA:            false,
		NotAfter:        time.Now().Add(validityHours),
		NotBefore:       time.Now(),
		SerialNumber:    big.NewInt(time.Now().UnixMilli()),
		Subject:         csr.Subject,
	}

	certClient, err := azcertificates.NewClient(plan.VaultURL.ValueString(), *r.azureCred, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating cert client",
			"Could not create cert client, unexpected error: "+err.Error(),
		)
		return
	}

	caCert, err := certClient.GetCertificate(ctx, plan.CAName.ValueString(), "", nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error getting ca cert",
			"Could not get ca cert, unexpected error: "+err.Error(),
		)
		return
	}

	parsedCACert, err := x509.ParseCertificate(caCert.CER)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing ca cert",
			"Could not parse ca cert, unexpected error: "+err.Error(),
		)
		return
	}

	signer, err := NewAzureKVSigner(ctx, *r.azureCred, plan.VaultURL.ValueString(), plan.CAName.ValueString(), plan.SignatureAlgorithm.ValueString(), parsedCACert.PublicKey)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating signer",
			"Could not create signer, unexpected error: "+err.Error(),
		)
		return
	}

	signedCert, err := x509.CreateCertificate(rand.Reader, template, parsedCACert, csr.PublicKey, signer)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating signed cert",
			"Could not create signed cert, unexpected error: "+err.Error(),
		)
	}

	signedPem := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signedCert,
	}

	// Map response body to schema and populate Computed attribute values
	plan.SignedCertPEM = types.StringValue(string(pem.EncodeToMemory(&signedPem)))

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *signResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *signResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *signResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// Configure adds the provider configured client to the resource.
func (r *signResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
