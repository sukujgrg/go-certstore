package certstore

import (
	"context"
	"crypto"
	"errors"
	"testing"
)

func TestFilterStoreIdentitiesRejectsNilFilter(t *testing.T) {
	store := &testStore{}

	_, err := filterStoreIdentities(context.Background(), store, nil)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestFindIdentitiesRejectsNilCertificateWithoutPanic(t *testing.T) {
	store := &testStore{
		idents: []Identity{
			&testIdentity{cert: nil},
		},
	}

	_, err := FindIdentities(context.Background(), store, FindIdentityOptions{})
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound, got %v", err)
	}
}

func TestFindTLSCertificateRejectsNilCertificateWithoutPanic(t *testing.T) {
	store := &testStore{
		idents: []Identity{
			&testIdentity{cert: nil},
		},
	}

	_, err := FindTLSCertificate(context.Background(), store, SelectOptions{})
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound, got %v", err)
	}
}

func TestSignerHashRejectsNilOptions(t *testing.T) {
	if _, err := signerHash(nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestNormalizePSSSaltLengthRejectsUnexpectedNegativeValue(t *testing.T) {
	if _, err := normalizePSSSaltLength(crypto.SHA256, -3); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}
