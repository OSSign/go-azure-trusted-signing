package goats

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"strings"
)

// Implements crypto.Signer interface for AzureTrustedSigning
func (ats AzureTrustedSigning) Public() crypto.PublicKey {
	cert, err := ats.GetCertificateChain(context.Background())
	if err != nil || len(cert) == 0 {
		return nil
	}

	return cert[0].PublicKey
}

// Implements crypto.Signer interface for AzureTrustedSigning
func (ats AzureTrustedSigning) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := strings.ReplaceAll(opts.HashFunc().String(), "-", "")

	if FromHashFunc[hashFunc] == "" {
		return nil, fmt.Errorf("currently unsupported hash function: %s", hashFunc)
	}

	req := SignRequest{
		Digest:             digest,
		SignatureAlgorithm: FromHashFunc[hashFunc],
	}
	response, err := ats.SignAndWait(context.Background(), req)
	if err != nil {
		return nil, err
	}

	if response.Status != "Completed" {
		return nil, fmt.Errorf("signing did not complete successfully, status: %s", response.Status)
	}

	return response.Signature, nil
}
