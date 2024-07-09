package provider

import (
	"context"
	"crypto"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func NewAzureKVSigner(ctx context.Context, cred azcore.TokenCredential, vaultURL string, keyName string, signatureAlgorithm string, publicKey crypto.PublicKey) (a *azureKVSigner, err error) {
	return &azureKVSigner{
		cred:               cred,
		ctx:                ctx,
		keyName:            keyName,
		publicKey:          publicKey,
		signatureAlgorithm: azkeys.SignatureAlgorithm(signatureAlgorithm),
		vaultURL:           vaultURL,
	}, nil
}

type azureKVSigner struct {
	cred               azcore.TokenCredential
	ctx                context.Context
	keyName            string
	publicKey          crypto.PublicKey
	signatureAlgorithm azkeys.SignatureAlgorithm
	vaultURL           string
}

func (a *azureKVSigner) Public() crypto.PublicKey {
	return a.publicKey
}

func (a *azureKVSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if a.keyName == "" {
		return make([]byte, 0), nil
	}

	keyClient, err := azkeys.NewClient(a.vaultURL, a.cred, nil)
	if err != nil {
		return nil, err
	}

	params := azkeys.SignParameters{
		Algorithm: &a.signatureAlgorithm,
		Value:     digest,
	}

	signResp, err := keyClient.Sign(a.ctx, a.keyName, "", params, nil)
	if err != nil {
		return nil, err
	}

	return signResp.Result, nil
}
