//go:build cgo

package certstore

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestNormalizeNSSProfileDir(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain path", in: "/tmp/nssdb", want: "sql:/tmp/nssdb"},
		{name: "sql prefix", in: "sql:/tmp/nssdb", want: "sql:/tmp/nssdb"},
		{name: "dbm prefix", in: "dbm:/tmp/nssdb", want: "dbm:/tmp/nssdb"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeNSSProfileDir(tc.in); got != tc.want {
				t.Fatalf("normalizeNSSProfileDir(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNSSIdentityMetadata(t *testing.T) {
	_, _, leaf, _ := newTestChain(t, "NSS CA", true)

	base := &pkcs11Identity{
		module: &pkcs11Module{
			module: "libsoftokn3.so",
			slotID: 2,
			tokenInfo: pkcs11.TokenInfo{
				Label:        "NSS Certificate DB",
				SerialNumber: "0001",
				Flags:        pkcs11.CKF_LOGIN_REQUIRED,
			},
		},
		keyID:   []byte{0x01, 0x02, 0x03},
		label:   "db-cert",
		certDER: leaf.Raw,
		cert:    leaf,
	}

	ident := &nssIdentity{
		pkcs11Identity: base,
		profileDir:     "/tmp/nssdb",
		profileSpec:    "sql:/tmp/nssdb",
	}

	if got := ident.Backend(); got != BackendNSS {
		t.Fatalf("Backend() = %q", got)
	}
	if got := ident.Label(); got != "db-cert" {
		t.Fatalf("Label() = %q", got)
	}
	if got := ident.ProfileDir(); got != "/tmp/nssdb" {
		t.Fatalf("ProfileDir() = %q", got)
	}
	if got := ident.ModulePath(); got != "libsoftokn3.so" {
		t.Fatalf("ModulePath() = %q", got)
	}
	if got := ident.TokenLabel(); got != "NSS Certificate DB" {
		t.Fatalf("TokenLabel() = %q", got)
	}
	if got := ident.TokenSerial(); got != "0001" {
		t.Fatalf("TokenSerial() = %q", got)
	}
	if got := ident.KeyType(); got != "ECDSA" {
		t.Fatalf("KeyType() = %q", got)
	}
	if got := ident.HardwareBackedState(); got != CapabilityNo {
		t.Fatalf("HardwareBackedState() = %v", got)
	}
	if got := ident.LoginRequiredState(); got != CapabilityYes {
		t.Fatalf("LoginRequiredState() = %v", got)
	}

	uri := ident.URI()
	if !strings.HasPrefix(uri, "nss:") {
		t.Fatalf("URI() = %q", uri)
	}
	if !strings.Contains(uri, "profile=sql:/tmp/nssdb") {
		t.Fatalf("URI() missing profile: %q", uri)
	}
	if !strings.Contains(uri, "module=libsoftokn3.so") {
		t.Fatalf("URI() missing module: %q", uri)
	}
	if !strings.Contains(uri, "token=NSS Certificate DB") {
		t.Fatalf("URI() missing token: %q", uri)
	}
	if !strings.Contains(uri, "id="+hex.EncodeToString(base.keyID)) {
		t.Fatalf("URI() missing key id: %q", uri)
	}
}

func TestNSSIdentityLabelFallsBackToCertificateSubject(t *testing.T) {
	_, _, leaf, _ := newTestChain(t, "NSS CA", true)

	ident := &nssIdentity{
		pkcs11Identity: &pkcs11Identity{
			module: &pkcs11Module{
				tokenInfo: pkcs11.TokenInfo{Label: "NSS Certificate DB"},
			},
			certDER: leaf.Raw,
			cert:    leaf,
		},
		profileDir:  "/tmp/nssdb",
		profileSpec: "sql:/tmp/nssdb",
	}

	if got := ident.Label(); got != leaf.Subject.CommonName {
		t.Fatalf("Label() = %q, want %q", got, leaf.Subject.CommonName)
	}
}

func TestSelectNSSSlotStopsDuringScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	reader := &fakeSlotReader{
		slots: []uint{1, 2},
		tokenInfo: map[uint]pkcs11.TokenInfo{
			1: {Label: "NSS Generic Crypto Services"},
			2: {Label: "NSS Certificate DB"},
		},
		onGetTokenInfo: func(slotID uint) {
			if slotID == 1 {
				cancel()
			}
		},
	}

	_, _, _, err := selectNSSSlotFromReader(ctx, reader)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
