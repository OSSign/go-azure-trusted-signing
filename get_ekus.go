package goats

import (
	"context"
	"fmt"

	"github.com/clysec/greq"
)

// Fetches the EKU list for the configured profile
// The EKUs are returned as a list of string OIDs
func (ats *AzureTrustedSigning) GetExtendedKeyUsages(ctx context.Context) ([]string, error) {
	token, err := ats.getToken(ctx)
	if err != nil {
		return nil, err
	}

	request, err := greq.
		GetRequest(ats.getURL("eku")).
		WithQueryParam("api-version", apiVersion).
		WithAuth(&greq.BearerAuth{Token: token, Prefix: "Bearer"}).
		WithHeader("Accept", "application/json").
		Execute()
	if err != nil {
		return nil, err
	}

	if request.StatusCode > 299 {
		response, err := request.BodyString()
		if err != nil {
			return nil, fmt.Errorf("error getting extended key usages: status %d: (failed to read response body)", request.StatusCode)
		}
		return nil, fmt.Errorf("error getting ekus: status %d: %s", request.StatusCode, response)
	}

	var ekus []string
	if err := request.BodyUnmarshalJson(&ekus); err != nil {
		return nil, err
	}

	return ekus, nil
}
