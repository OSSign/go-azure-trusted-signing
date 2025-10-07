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
	"go.mozilla.org/pkcs7"
)

func TestGetCertificateChain(t *testing.T) {
	c := goats.NewClient(goats.RegionEastUS, fakeToken, "acct", "profile")

	rootPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	intermediatePriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	endEntityPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:      pkix.Name{Organization: []string{"Root CA"}},
		SerialNumber: big.NewInt(1),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}, &x509.Certificate{}, rootPriv.Public(), rootPriv)
	if err != nil {
		t.Fatalf("failed to create root certificate: %v", err)
	}

	intermediateCertDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:      pkix.Name{Organization: []string{"Intermediate CA"}},
		SerialNumber: big.NewInt(2),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}, &x509.Certificate{}, intermediatePriv.Public(), rootPriv)
	if err != nil {
		t.Fatalf("failed to create intermediate certificate: %v", err)
	}

	endEntityCertDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:      pkix.Name{Organization: []string{"End Entity"}},
		SerialNumber: big.NewInt(3),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, &x509.Certificate{}, endEntityPriv.Public(), intermediatePriv)
	if err != nil {
		t.Fatalf("failed to create end-entity certificate: %v", err)
	}

	chainData := []byte{}
	chainData = append(chainData, endEntityCertDER...)
	chainData = append(chainData, intermediateCertDER...)
	chainData = append(chainData, rootCertDER...)

	degen, err := pkcs7.DegenerateCertificate(chainData)
	if err != nil {
		t.Fatalf("failed to create degenerate PKCS#7: %v", err)
	}

	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/pkcs7-mime")
	rec.Header().Set("x-ms-request-id", "ms-request-id-example")

	rec.Write(degen)

	c.SetHTTPClient(GetMockHttpClient(
		rec.Result(),
		nil,
	))

	chain, err := c.GetCertificateChain(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain) != 3 {
		t.Fatalf("expected 3 certificates in chain, got %d", len(chain))
	}

	if chain[0].SerialNumber.Cmp(big.NewInt(3)) != 0 {
		t.Error("expected end-entity certificate with serial number 3")
	}
	if chain[1].SerialNumber.Cmp(big.NewInt(2)) != 0 {
		t.Error("expected intermediate certificate with serial number 2")
	}
	if chain[2].SerialNumber.Cmp(big.NewInt(1)) != 0 {
		t.Error("expected root certificate with serial number 1")
	}
}
