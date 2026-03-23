package certstore

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"
	"time"
)

type closableTestSigner struct {
	closed bool
}

func (s *closableTestSigner) Public() crypto.PublicKey { return nil }
func (s *closableTestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
func (s *closableTestSigner) Close() error {
	s.closed = true
	return nil
}

func TestCloseSigner(t *testing.T) {
	signer := &closableTestSigner{}
	if err := CloseSigner(signer); err != nil {
		t.Fatal(err)
	}
	if !signer.closed {
		t.Fatal("expected signer to be closed")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := CloseSigner(key); err != nil {
		t.Fatal(err)
	}
}

func TestCloseSignerNilIsNoop(t *testing.T) {
	if err := CloseSigner(nil); err != nil {
		t.Fatalf("CloseSigner(nil) returned %v", err)
	}
}

func TestFindIdentity(t *testing.T) {
	now := time.Now()
	_, _, certA, keyA := newTestChain(t, "Select CA A", true)
	_, _, certB, keyB := newTestChain(t, "Select CA B", true)

	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:   certA,
				signer: keyA,
				info: testIdentityInfo{
					label:    "software",
					backend:  BackendPKCS11,
					keyType:  "ECDSA",
					hardware: false,
					uri:      "pkcs11:software",
				},
			},
			&testIdentity{
				cert:   certB,
				signer: keyB,
				info: testIdentityInfo{
					label:    "hardware",
					backend:  BackendPKCS11,
					keyType:  "ECDSA",
					hardware: true,
					uri:      "pkcs11:hardware",
				},
			},
		},
	}

	ident, err := FindIdentity(context.Background(), store, FindIdentityOptions{
		Backend:              BackendPKCS11,
		ValidOnly:            true,
		PreferHardwareBacked: true,
		Now:                  now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ident.Close()
	info := ident.(IdentityInfo)
	if info.Label() != "hardware" {
		t.Fatalf("expected hardware identity, got %q", info.Label())
	}
}

func TestFindIdentityHardwarePreferenceDominatesLongExpiry(t *testing.T) {
	now := time.Now()

	// Software identity with a 10-year certificate (3650 days remaining).
	// Before the fix, its expiry score (3650) would exceed the hardware
	// bonus (1000), causing a software identity to outrank a hardware one.
	_, _, softCert, softKey := newTestChainWithExpiry(t, "Long Expiry CA", true, now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	// Hardware identity with a 1-year certificate.
	_, _, hwCert, hwKey := newTestChainWithExpiry(t, "Short Expiry CA", true, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:   softCert,
				signer: softKey,
				info: testIdentityInfo{
					label:    "software-long",
					backend:  BackendPKCS11,
					keyType:  "ECDSA",
					hardware: false,
					uri:      "pkcs11:software-long",
				},
			},
			&testIdentity{
				cert:   hwCert,
				signer: hwKey,
				info: testIdentityInfo{
					label:    "hardware-short",
					backend:  BackendPKCS11,
					keyType:  "ECDSA",
					hardware: true,
					uri:      "pkcs11:hardware-short",
				},
			},
		},
	}

	ident, err := FindIdentity(context.Background(), store, FindIdentityOptions{
		Backend:              BackendPKCS11,
		ValidOnly:            true,
		PreferHardwareBacked: true,
		Now:                  now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ident.Close()
	info := ident.(IdentityInfo)
	if info.Label() != "hardware-short" {
		t.Fatalf("expected hardware identity to win despite shorter expiry, got %q", info.Label())
	}
}

func TestFindIdentitiesFiltersMetadata(t *testing.T) {
	_, _, certA, keyA := newTestChain(t, "Select CA A", true)
	_, _, certB, keyB := newTestChain(t, "Select CA B", true)

	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:   certA,
				signer: keyA,
				info: testIdentityInfo{
					label:    "wanted",
					backend:  BackendPKCS11,
					keyType:  "ECDSA",
					hardware: true,
					uri:      "pkcs11:wanted",
				},
			},
			&testIdentity{
				cert:   certB,
				signer: keyB,
				info: testIdentityInfo{
					label:    "other",
					backend:  BackendPKCS11,
					keyType:  "ECDSA",
					hardware: false,
					uri:      "pkcs11:other",
				},
			},
		},
	}

	idents, err := FindIdentities(context.Background(), store, FindIdentityOptions{
		Label:                 "wanted",
		RequireHardwareBacked: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(idents) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(idents))
	}
	defer idents[0].Close()
	if info := idents[0].(IdentityInfo); info.URI() != "pkcs11:wanted" {
		t.Fatalf("unexpected identity URI %q", info.URI())
	}
}
