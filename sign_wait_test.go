package goats_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	goats "github.com/ossign/go-azure-trusted-signing"
)

func TestSignAndWait(t *testing.T) {
	c := goats.NewClient(goats.RegionEastUS, fakeToken, "acct", "profile")

	requestChain := []*http.Response{}

	initialRec := httptest.NewRecorder()
	initialRec.Header().Set("Content-Type", "application/json")
	initialRec.Header().Set("x-ms-request-id", "ms-request-id-example")
	initialRec.WriteString(`{"operationId":"signing-request-id-example","status":"Running"}`)
	requestChain = append(requestChain, initialRec.Result())

	statusInProgressRec := httptest.NewRecorder()
	statusInProgressRec.Header().Set("Content-Type", "application/json")
	statusInProgressRec.Header().Set("x-ms-request-id", "ms-request-id-example")
	statusInProgressRec.WriteString(`{"operationId":"signing-request-id-example","status":"InProgress"}`)

	requestChain = append(requestChain, statusInProgressRec.Result())

	statusInProgressRec2 := httptest.NewRecorder()
	statusInProgressRec2.Header().Set("Content-Type", "application/json")
	statusInProgressRec2.Header().Set("x-ms-request-id", "ms-request-id-example")
	statusInProgressRec2.WriteString(`{"operationId":"signing-request-id-example","status":"InProgress"}`)

	requestChain = append(requestChain, statusInProgressRec2.Result())

	statusInProgressRec3 := httptest.NewRecorder()
	statusInProgressRec3.Header().Set("Content-Type", "application/json")
	statusInProgressRec3.Header().Set("x-ms-request-id", "ms-request-id-example")
	statusInProgressRec3.WriteString(`{"operationId":"signing-request-id-example","status":"InProgress"}`)

	requestChain = append(requestChain, statusInProgressRec3.Result())

	statusSuccessRec := httptest.NewRecorder()
	statusSuccessRec.Header().Set("Content-Type", "application/json")
	statusSuccessRec.Header().Set("x-ms-request-id", "ms-request-id-example")

	statusResponse := map[string]string{
		"operationId": "signing-request-id-example",
		"status":      "Succeeded",
		"signature":   base64.StdEncoding.EncodeToString([]byte("this-is-some-signed-data")),
	}

	enc, err := json.Marshal(statusResponse)
	if err != nil {
		t.Fatalf("failed to marshal status response: %v", err)
	}

	statusSuccessRec.Write(enc)
	requestChain = append(requestChain, statusSuccessRec.Result())

	c.SetHTTPClient(GetMockHttpSeries(requestChain, nil))

	timeStart := time.Now()

	resp, err := c.SignAndWait(t.Context(), goats.SignRequest{
		SignatureAlgorithm: goats.RS256,
		Digest:             []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	timeEnd := time.Now()

	if timeEnd.Sub(timeStart) < 5*time.Second {
		t.Fatalf("expected at least 5 seconds to have passed due to wait loop, got %v", timeEnd.Sub(timeStart))
	}

	if resp.OperationId != "signing-request-id-example" {
		t.Errorf("expected operationId to be signing-request-id-example, got %s", resp.OperationId)
	}

	if resp.Status != goats.StatusSucceeded {
		t.Errorf("expected status to be Running, got %s", resp.Status)
	}

	expectedSignature := "this-is-some-signed-data"
	if string(resp.Signature) != expectedSignature {
		t.Errorf("expected signature to be %s, got %s", expectedSignature, string(resp.Signature))
	}
}
