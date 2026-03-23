package certstore

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestFilterStoreIdentitiesRejectsNilFilter(t *testing.T) {
	store := &testStore{}

	_, err := filterStoreIdentities(context.Background(), store, nil)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestFilterStoreIdentitiesRejectsNilStore(t *testing.T) {
	_, err := filterStoreIdentities(context.Background(), nil, func(*x509.Certificate) bool { return true })
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestFindIdentitiesRejectsNilStore(t *testing.T) {
	_, err := FindIdentities(context.Background(), nil, FindIdentityOptions{})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestFindTLSCertificateRejectsNilStore(t *testing.T) {
	_, err := FindTLSCertificate(context.Background(), nil, SelectOptions{})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestFilterStoreIdentitiesSkipsNilIdentityWithoutPanic(t *testing.T) {
	store := &testStore{
		idents: []Identity{nil},
	}

	idents, err := filterStoreIdentities(context.Background(), store, func(*x509.Certificate) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if len(idents) != 0 {
		t.Fatalf("expected no identities, got %d", len(idents))
	}
}

func TestFindIdentitiesRejectsNilIdentityWithoutPanic(t *testing.T) {
	store := &testStore{
		idents: []Identity{nil},
	}

	_, err := FindIdentities(context.Background(), store, FindIdentityOptions{})
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound, got %v", err)
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normalizePSSSaltLength(&key.PublicKey, crypto.SHA256, -3); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
	}
}

func TestNormalizePSSSaltLengthAutoUsesMaximumSalt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	got, err := normalizePSSSaltLength(&key.PublicKey, crypto.SHA256, rsa.PSSSaltLengthAuto)
	if err != nil {
		t.Fatal(err)
	}

	want := uint(key.PublicKey.Size() - crypto.SHA256.Size() - 2)
	if got != want {
		t.Fatalf("normalizePSSSaltLength(auto) = %d, want %d", got, want)
	}
}

func TestIsCertificateCurrentlyValidIncludesBoundaryInstants(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
	}

	if !isCertificateCurrentlyValid(cert, now) {
		t.Fatal("expected NotBefore boundary to count as valid")
	}
	if !isCertificateCurrentlyValid(cert, cert.NotAfter) {
		t.Fatal("expected NotAfter boundary to count as valid")
	}
}

func TestByteSlicePtrReturnsNilForEmptySlice(t *testing.T) {
	if ptr := byteSlicePtr(nil); ptr != nil {
		t.Fatalf("expected nil pointer for nil slice, got %v", ptr)
	}
	if ptr := byteSlicePtr([]byte{}); ptr != nil {
		t.Fatalf("expected nil pointer for empty slice, got %v", ptr)
	}
}

func TestByteSliceStringViewAvoidsGoStringCopy(t *testing.T) {
	secret := []byte("secret")
	view := byteSliceStringView(secret)

	secret[0] = 'x'
	if view != "xecret" {
		t.Fatalf("expected string view to reflect backing buffer updates, got %q", view)
	}

	if empty := byteSliceStringView(nil); empty != "" {
		t.Fatalf("expected empty string for nil slice, got %q", empty)
	}
}
