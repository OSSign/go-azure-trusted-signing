package goats_test

import (
	"crypto"
	"testing"

	goats "github.com/ossign/go-azure-trusted-signing"
)

func wantsCryptoSigner(s crypto.Signer) {}

func TestMatchesInterface(t *testing.T) {
	inst := goats.AzureTrustedSigning{}
	wantsCryptoSigner(&inst)
}
