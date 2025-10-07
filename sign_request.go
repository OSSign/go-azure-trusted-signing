package goats

import (
	"context"
	"fmt"

	"github.com/clysec/greq"
)

// Requests a signature for the given SignRequest. Returns a SignStatus with the operation ID and initial status.
// The actual signature must be fetched using GetSignatureStatus with the operation ID, and may require multiple
// calls until the status is "Completed".
// For a complete signing operation, see SignAndWait.
func (ats *AzureTrustedSigning) RequestSignature(ctx context.Context, req SignRequest) (*SignStatus, error) {
	token, err := ats.getToken(ctx)
	if err != nil {
		return nil, err
	}

	request, err := greq.
		PostRequest(ats.getURL()).
		WithClient(ats.client).
		WithQueryParam("api-version", apiVersion).
		WithAuth(&greq.BearerAuth{Token: token, Prefix: "Bearer"}).
		WithHeader("Accept", "application/json").
		WithJSONBody(req, nil).
		Execute()
	if err != nil {
		return nil, err
	}

	if request.StatusCode > 299 {
		response, err := request.BodyString()
		if err != nil {
			return nil, fmt.Errorf("error requesting signature: status %d: (failed to read response body)", request.StatusCode)
		}
		return nil, fmt.Errorf("error requesting signature: status %d: %s", request.StatusCode, response)
	}

	var signStatus SignStatus
	if err := request.BodyUnmarshalJson(&signStatus); err != nil {
		return nil, err
	}

	return &signStatus, nil
}
