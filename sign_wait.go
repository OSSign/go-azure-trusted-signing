package goats

import (
	"context"
	"time"
)

// Implements the full signing operation: Requests a signature and waits for it to complete
// Returns the completed SignStatus, or an error if the operation failed
func (ats *AzureTrustedSigning) SignAndWait(ctx context.Context, req SignRequest) (*SignStatus, error) {
	status, err := ats.RequestSignature(ctx, req)
	if err != nil {
		return status, err
	}

	for status.Status == StatusRunning || status.Status == StatusInProgress {
		time.Sleep(2 * time.Second)
		status, err = ats.GetSignatureStatus(ctx, status.OperationId)
		if err != nil {
			return status, err
		}
	}

	return status, err
}
