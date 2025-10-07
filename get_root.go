package goats

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/clysec/greq"
)

// Fetches the root certificate for the configured profile
func (ats *AzureTrustedSigning) GetRootCertificate(ctx context.Context) (*x509.Certificate, error) {
	if ats.root != nil {
		return ats.root, nil
	}

	token, err := ats.getToken(ctx)
	if err != nil {
		return nil, err
	}

	request, err := greq.
		GetRequest(ats.getURL("rootcert")).
		WithQueryParam("api-version", apiVersion).
		WithAuth(&greq.BearerAuth{Token: token, Prefix: "Bearer"}).
		WithHeader("Accept", "application/x-x509-ca-cert, application/json").
		Execute()
	if err != nil {
		return nil, err
	}

	if request.StatusCode > 299 {
		response, err := request.BodyString()
		if err != nil {
			return nil, fmt.Errorf("error getting root certificate: status %d: (failed to read response body)", request.StatusCode)
		}
		return nil, fmt.Errorf("error getting root certificate: status %d: %s", request.StatusCode, response)
	}

	body, err := request.BodyBytes()
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(body)
	if err != nil {
		return nil, err
	}

	ats.root = cert
	return cert, nil
}
