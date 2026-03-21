//go:build cgo

package certstore

import (
	"crypto"
	"testing"

	"github.com/miekg/pkcs11"
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

func TestPKCS11IdentityInfoMethodsFallbacks(t *testing.T) {
	id := &pkcs11Identity{
		module: &pkcs11Module{
			module: "/tmp/test-pkcs11.so",
			slotID: 1,
		},
		label: "fallback-label",
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
