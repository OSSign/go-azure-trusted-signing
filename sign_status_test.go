package goats_test

import (
	"net/http/httptest"
	"testing"

	goats "github.com/ossign/go-azure-trusted-signing"
)

func TestGetSignatureStatus(t *testing.T) {
	c := goats.NewClient(goats.RegionEastUS, fakeToken, "acct", "profile")
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.Header().Set("x-ms-request-id", "ms-request-id-example")
	rec.WriteString(`{"operationId":"signing-request-id-example","status":"Running"}`)

	c.SetHTTPClient(GetMockHttpClient(
		rec.Result(),
		nil,
	))

	resp, err := c.GetSignatureStatus(t.Context(), "signing-request-id-example")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if resp.OperationId != "signing-request-id-example" {
		t.Errorf("expected operationId to be signing-request-id-example, got %s", resp.OperationId)
	}

	if resp.Status != goats.StatusRunning {
		t.Errorf("expected status to be Running, got %s", resp.Status)
	}
}
