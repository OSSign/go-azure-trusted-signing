package goats

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/clysec/greq"
	"go.mozilla.org/pkcs7"
)

// Fetches the certificate chain for the configured profile
func (ats *AzureTrustedSigning) GetCertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	if ats.chain != nil {
		return ats.chain.Certificates, nil
	}

	token, err := ats.getToken(ctx)
	if err != nil {
		return nil, err
	}

	request, err := greq.
		GetRequest(ats.getURL("certchain")).
		WithQueryParam("api-version", apiVersion).
		WithAuth(&greq.BearerAuth{Token: token, Prefix: "Bearer"}).
		WithHeader("Accept", "application/pkcs7-mime, application/x-x509-ca-cert, application/json").
		Execute()
	if err != nil {
		return nil, err
	}

	if request.StatusCode > 299 {
		response, err := request.BodyString()
		if err != nil {
			return nil, fmt.Errorf("error getting certificate chain: status %d: (failed to read response body)", request.StatusCode)
		}
		return nil, fmt.Errorf("error getting certificate chain: status %d: %s", request.StatusCode, response)
	}

	body, err := request.BodyBytes()
	if err != nil {
		return nil, err
	}

	certificates, err := pkcs7.Parse(body)
	if err != nil {
		return nil, err
	}

	ats.chain = certificates

	return certificates.Certificates, nil
}
