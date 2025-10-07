package goats_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"testing"

	goats "github.com/ossign/go-azure-trusted-signing"
)

func TestGetRootCertificate(t *testing.T) {
	c := goats.NewClient(goats.RegionEastUS, fakeToken, "acct", "profile")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"SE"},
			Organization: []string{"Test Org"},
		},
		SerialNumber: big.NewInt(987654321),
	}, &x509.Certificate{}, priv.Public(), priv)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/pkix-cert")
	rec.Header().Set("x-ms-request-id", "ms-request-id-example")
	rec.Write(cert)

	c.SetHTTPClient(GetMockHttpClient(
		rec.Result(),
		nil,
	))

	root, err := c.GetRootCertificate(t.Context())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if root == nil || root.SerialNumber.Cmp(big.NewInt(987654321)) != 0 {
		t.Error("expected root certificate with serial number 987654321")
	}

	if root.Subject.Country[0] != "SE" || root.Subject.Organization[0] != "Test Org" {
		t.Error("expected root certificate with correct subject")
	}
}
