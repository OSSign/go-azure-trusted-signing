package goats

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"go.mozilla.org/pkcs7"
)

// The current API Version of Azure Trsuted Signing this library is built for
const apiVersion = "2022-06-15-preview"

// The region where the AzureTrustedSigning account is placed in
// East US			EastUS			eus
// West US			WestUS			wus
// West Central US	WestCentralUS	wcus
// West US 2		WestUS2			wus2
// North Europe		NorthEurope		neu
// West Europe		WestEurope		weu
type AzureTrustedSigningRegion string

const (
	RegionEastUS        AzureTrustedSigningRegion = "eus"
	RegionWestUS        AzureTrustedSigningRegion = "wus"
	RegionWestCentralUS AzureTrustedSigningRegion = "wcus"
	RegionWestUS2       AzureTrustedSigningRegion = "wus2"
	RegionNorthEurope   AzureTrustedSigningRegion = "neu"
	RegionWestEurope    AzureTrustedSigningRegion = "weu"
)

// AzureTrustedSigning contains the configuration for accessing Azure Trusted Signing
type AzureTrustedSigning struct {
	// The region your Azure Trusted Signing instance is located in
	Region AzureTrustedSigningRegion

	// The credential provider to use for authentication
	Credential azcore.TokenCredential

	// The Trusted Signing account name
	AccountName string `json:"accountName" yaml:"accountName"`

	// The Trusted Signing certificate profile name
	ProfileName string `json:"profileName" yaml:"profileName"`

	token *azcore.AccessToken

	root  *x509.Certificate
	chain *pkcs7.PKCS7
	ekus  []string

	client *http.Client
}

// Create a new Azure Trusted Signing client with a custom credential provider from the Azure SDK
func NewClient(region AzureTrustedSigningRegion, credential azcore.TokenCredential, accountName, profileName string) *AzureTrustedSigning {
	return &AzureTrustedSigning{
		Region:      region,
		Credential:  credential,
		AccountName: accountName,
		ProfileName: profileName,

		client: http.DefaultClient,
	}
}

// Create a new Azure Trusted Signing client with the DefaultAzureCredential from the Azure SDK
func NewDefaultClient(region AzureTrustedSigningRegion, accountName, profileName string) (*AzureTrustedSigning, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}

	return &AzureTrustedSigning{
		Region:      region,
		Credential:  cred,
		AccountName: accountName,
		ProfileName: profileName,

		client: http.DefaultClient,
	}, nil
}

// Create a new Azure Trusted Signing client with the ClientSecretCredential from the Azure SDK
// This requires a tenant ID, client ID and client secret of an Azure AD application with access to the Code Signing service
func NewClientSecretClient(region AzureTrustedSigningRegion, tenantID, clientID, clientSecret, accountName, profileName string) (*AzureTrustedSigning, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, err
	}

	return &AzureTrustedSigning{
		Region:      region,
		Credential:  cred,
		AccountName: accountName,
		ProfileName: profileName,

		client: http.DefaultClient,
	}, nil
}

// Manually override the HTTP Client used for the connection
func (ats *AzureTrustedSigning) SetHTTPClient(client *http.Client) {
	ats.client = client
}

// baseURL returns the base URL for the Azure Trusted Signing instance in the specified region
func (ats *AzureTrustedSigning) getURL(path ...string) string {
	base := fmt.Sprintf("https://%s.codesigning.azure.net/codesigningaccounts/%s/certificateprofiles/%s/sign", string(ats.Region), ats.AccountName, ats.ProfileName)

	if len(path) > 0 {
		base = base + "/" + strings.Join(path, "/")
	}

	return base
}

// getToken retrieves a valid access token from the credential provider, caching it until it is close to expiration
func (ats *AzureTrustedSigning) getToken(ctx context.Context) (string, error) {
	if ats.token != nil && ats.token.ExpiresOn.After(time.Now().Add(5*time.Minute)) {
		return ats.token.Token, nil
	}

	token, err := ats.Credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://codesigning.azure.net/.default"},
	})
	if err != nil {
		return "", err
	}

	ats.token = &token
	return ats.token.Token, nil
}
