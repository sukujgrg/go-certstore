//go:build cgo

package certstore

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"testing"

	"github.com/sukujgrg/go-certstore/internal/pkcs11"
)

func TestPKCS11IdentityInfoMethods(t *testing.T) {
	_, _, cert, _ := newTestChain(t, "PKCS11 Info CA", true)
	id := &pkcs11Identity{
		module: &pkcs11Module{
			module: "/tmp/test-pkcs11.so",
			slotID: 9,
			slotInfo: pkcs11.SlotInfo{
				Flags: pkcs11.CKF_HW_SLOT,
			},
			tokenInfo: pkcs11.TokenInfo{
				Label:        "Test Token                       ",
				SerialNumber: "123456                          ",
				Flags:        pkcs11.CKF_LOGIN_REQUIRED,
			},
		},
		backend:    BackendPKCS11,
		modulePath: "/tmp/test-pkcs11.so",
		slotID:     9,
		slotInfo:   pkcs11.SlotInfo{Flags: pkcs11.CKF_HW_SLOT},
		tokenInfo: pkcs11.TokenInfo{
			Label:        "Test Token                       ",
			SerialNumber: "123456                          ",
			Flags:        pkcs11.CKF_LOGIN_REQUIRED,
		},
		keyID:   []byte{0x01, 0x02},
		label:   "client-key",
		cert:    cert,
		certDER: cert.Raw,
	}

	if got := id.Label(); got != "client-key" {
		t.Fatalf("Label() = %q", got)
	}
	if got := id.Backend(); got != BackendPKCS11 {
		t.Fatalf("Backend() = %q", got)
	}
	if got := id.KeyType(); got != "ECDSA" {
		t.Fatalf("KeyType() = %q", got)
	}
	if !id.IsHardwareBacked() {
		t.Fatal("IsHardwareBacked() = false")
	}
	if !id.RequiresLogin() {
		t.Fatal("RequiresLogin() = false")
	}
	if got := id.HardwareBackedState(); got != CapabilityYes {
		t.Fatalf("HardwareBackedState() = %v", got)
	}
	if got := id.LoginRequiredState(); got != CapabilityYes {
		t.Fatalf("LoginRequiredState() = %v", got)
	}
	if got := id.ModulePath(); got != "/tmp/test-pkcs11.so" {
		t.Fatalf("ModulePath() = %q", got)
	}
	if got := id.SlotID(); got != 9 {
		t.Fatalf("SlotID() = %d", got)
	}
	if got := id.TokenLabel(); got != "Test Token" {
		t.Fatalf("TokenLabel() = %q", got)
	}
	if got := id.TokenSerial(); got != "123456" {
		t.Fatalf("TokenSerial() = %q", got)
	}
	if got := id.URI(); got == "" {
		t.Fatal("URI() is empty")
	}
}

func TestPKCS11ClosedResourcesFailGracefully(t *testing.T) {
	store := &pkcs11Store{}
	if _, err := store.Identities(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Identities() error = %v, want ErrClosed", err)
	}

	id := &pkcs11Identity{
		backend:    BackendPKCS11,
		modulePath: "/tmp/test-pkcs11.so",
		slotID:     7,
		tokenInfo:  pkcs11.TokenInfo{Label: "closed-token"},
	}
	if _, err := id.Signer(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Signer() error = %v, want ErrClosed", err)
	}
	if got := id.ModulePath(); got != "/tmp/test-pkcs11.so" {
		t.Fatalf("ModulePath() after close = %q", got)
	}
	if got := id.TokenLabel(); got != "closed-token" {
		t.Fatalf("TokenLabel() after close = %q", got)
	}
	if got := id.URI(); got == "" {
		t.Fatal("URI() after close is empty")
	}
}

func TestClassifyPKCS11SignError(t *testing.T) {
	capabilityErr := classifyPKCS11SignError("sign", pkcs11.CKR_MECHANISM_INVALID)
	if !errors.Is(capabilityErr, ErrMechanismUnsupported) {
		t.Fatalf("capability error = %v, want ErrMechanismUnsupported", capabilityErr)
	}
	if !errors.Is(capabilityErr, pkcs11.CKR_MECHANISM_INVALID) {
		t.Fatalf("capability error lost PKCS#11 cause: %v", capabilityErr)
	}

	operationalErr := classifyPKCS11SignError("sign", pkcs11.CKR_PIN_LOCKED)
	if errors.Is(operationalErr, ErrMechanismUnsupported) {
		t.Fatalf("operational error misclassified: %v", operationalErr)
	}
	if !errors.Is(operationalErr, pkcs11.CKR_PIN_LOCKED) {
		t.Fatalf("operational error lost PKCS#11 cause: %v", operationalErr)
	}
}

func TestPKCS11IdentityConcurrentClose(t *testing.T) {
	_, _, cert, _ := newTestChain(t, "PKCS11 Concurrent Close CA", true)
	id := &pkcs11Identity{
		module:     &pkcs11Module{closed: true},
		backend:    BackendPKCS11,
		modulePath: "/tmp/test-pkcs11.so",
		tokenInfo:  pkcs11.TokenInfo{Label: "test-token"},
		certDER:    cert.Raw,
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 100 {
				_, _ = id.Certificate(context.Background())
				_, _ = id.Signer(context.Background())
				_ = id.URI()
			}
		}()
	}
	close(start)
	id.Close()
	wg.Wait()
}

func TestPKCS11StoreConcurrentClose(t *testing.T) {
	store := &pkcs11Store{module: &pkcs11Module{closed: true}}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 100 {
				_, _ = store.Identities(context.Background())
			}
		}()
	}
	close(start)
	store.Close()
	wg.Wait()
}

func TestPKCS11IdentityInfoMethodsFallbacks(t *testing.T) {
	id := &pkcs11Identity{
		module: &pkcs11Module{
			module: "/tmp/test-pkcs11.so",
			slotID: 1,
		},
		modulePath: "/tmp/test-pkcs11.so",
		slotID:     1,
		label:      "fallback-label",
	}

	if got := id.KeyType(); got != "" {
		t.Fatalf("KeyType() = %q", got)
	}
	if got := id.HardwareBackedState(); got != CapabilityNo {
		t.Fatalf("HardwareBackedState() = %v", got)
	}
	if got := id.LoginRequiredState(); got != CapabilityNo {
		t.Fatalf("LoginRequiredState() = %v", got)
	}
	if got := id.URI(); got == "" {
		t.Fatal("URI() is empty")
	}
}

func TestPKCS11SignerHelpers(t *testing.T) {
	_, _, _, key := newTestChain(t, "Signer Helper CA", true)

	signer := &pkcs11Signer{pub: key.Public()}
	if signer.Public() != key.Public() {
		t.Fatal("Public() did not return the underlying key")
	}
	if got := signer.supportedSignatureAlgorithms(); len(got) == 0 {
		t.Fatal("supportedSignatureAlgorithms() returned no schemes")
	}

	mechs, input, err := pkcs11SignatureMechanism(struct{}{}, []byte{1, 2, 3}, crypto.Hash(0))
	if err == nil {
		t.Fatalf("expected unsupported mechanism error, got mech=%v input=%v", mechs, input)
	}
	if mechs != nil || input != nil {
		t.Fatalf("expected nil mechanism/input on error, got %v %v", mechs, input)
	}
}

func TestPKCS11HashHelpersUnsupported(t *testing.T) {
	if _, _, err := pkcs11HashParams(crypto.Hash(0)); err != ErrUnsupportedHash {
		t.Fatalf("pkcs11HashParams() error = %v", err)
	}
	if _, err := hashOID(crypto.Hash(0)); err != ErrUnsupportedHash {
		t.Fatalf("hashOID() error = %v", err)
	}
}
