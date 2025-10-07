package goats

import (
	"context"
	"fmt"

	"github.com/clysec/greq"
)

// Fetches the status of a signing operation given its operation ID.
// The status may be "NotStarted", "InProgress", "Completed", "Failed" or "NotFound".
// If the status is "Completed", signature and certificate chain will be returned.
func (ats *AzureTrustedSigning) GetSignatureStatus(ctx context.Context, operationId string) (*SignStatus, error) {
	token, err := ats.getToken(ctx)
	if err != nil {
		return nil, err
	}

	request, err := greq.
		GetRequest(ats.getURL(operationId)).
		WithClient(ats.client).
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
