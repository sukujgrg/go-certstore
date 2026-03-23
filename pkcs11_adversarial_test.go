//go:build cgo

package certstore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

func TestPKCS11SignatureMechanismRejectsNilSignerOptions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mech, input, err := pkcs11SignatureMechanism(&key.PublicKey, make([]byte, crypto.SHA256.Size()), nil)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
	if mech != nil || input != nil {
		t.Fatalf("expected nil mechanism/input on error, got %v %v", mech, input)
	}
}
