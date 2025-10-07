package goats_test

import (
	"net/http/httptest"
	"testing"

	goats "github.com/ossign/go-azure-trusted-signing"
)

func TestGetExtendedKeyUsages(t *testing.T) {
	c := goats.NewClient(goats.RegionEastUS, fakeToken, "acct", "profile")
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/json")
	rec.Header().Set("x-ms-request-id", "ms-request-id-example")
	rec.WriteString(`["1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583"]`)

	c.SetHTTPClient(GetMockHttpClient(
		rec.Result(),
		nil,
	))

	ekus, err := c.GetExtendedKeyUsages(t.Context())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(ekus) != 1 || ekus[0] != "1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583" {
		t.Error("expected ekus to contain 1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583")
	}
}
