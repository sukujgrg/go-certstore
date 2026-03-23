//go:build darwin && cgo

package certstore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

func TestMacIdentityImplementsIdentityInfo(t *testing.T) {
	_, _, cert, _ := newTestChain(t, "Darwin Info CA", true)

	id := &macIdentity{cert: cert, certRaw: cert.Raw}

	if got := id.Label(); got != cert.Subject.CommonName {
		t.Fatalf("Label() = %q, want %q", got, cert.Subject.CommonName)
	}
	if got := id.Backend(); got != BackendDarwin {
		t.Fatalf("Backend() = %q, want %q", got, BackendDarwin)
	}
	if got := id.KeyType(); got != "ECDSA" {
		t.Fatalf("KeyType() = %q, want ECDSA", got)
	}
	if id.IsHardwareBacked() {
		t.Fatal("IsHardwareBacked() = true, want false")
	}
	if id.RequiresLogin() {
		t.Fatal("RequiresLogin() = true, want false")
	}
	if got := id.HardwareBackedState(); got != CapabilityUnknown {
		t.Fatalf("HardwareBackedState() = %v, want %v", got, CapabilityUnknown)
	}
	if got := id.LoginRequiredState(); got != CapabilityUnknown {
		t.Fatalf("LoginRequiredState() = %v, want %v", got, CapabilityUnknown)
	}
	if got := id.URI(); !strings.HasPrefix(got, "darwin-keychain:sha256=") {
		t.Fatalf("URI() = %q", got)
	}
}

func TestCurrentNativeBackendDarwin(t *testing.T) {
	if got := currentNativeBackend(); got != BackendDarwin {
		t.Fatalf("currentNativeBackend() = %q, want %q", got, BackendDarwin)
	}
}

func TestMacSignerAlgorithmRejectsPSSSaltLengthAutoDowngrade(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer := &macSigner{pub: &key.PublicKey}
	_, err = signer.algorithm(&rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if !errors.Is(err, ErrMechanismUnsupported) {
		t.Fatalf("expected ErrMechanismUnsupported, got %v", err)
	}
}
