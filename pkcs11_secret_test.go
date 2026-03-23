//go:build cgo

package certstore

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestWipeBytes(t *testing.T) {
	secret := []byte("secret")
	wipeBytes(secret)
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("secret[%d] = %d, want 0", i, b)
		}
	}
}

func TestLoginWipesCredentialOnPromptError(t *testing.T) {
	credential := []byte("secret-pin")
	promptErr := errors.New("prompt cancelled")

	m := &pkcs11Module{
		tokenInfo: pkcs11.TokenInfo{Flags: pkcs11.CKF_LOGIN_REQUIRED},
		prompt: func(PromptInfo) ([]byte, error) {
			return credential, promptErr
		},
	}

	err := m.login(context.Background(), 0)
	if !errors.Is(err, promptErr) {
		t.Fatalf("expected prompt error, got %v", err)
	}

	for i, b := range credential {
		if b != 0 {
			t.Fatalf("credential[%d] = %d after prompt error, want 0", i, b)
		}
	}
}

func TestLoginWipesNilCredentialOnPromptErrorWithoutPanic(t *testing.T) {
	m := &pkcs11Module{
		tokenInfo: pkcs11.TokenInfo{Flags: pkcs11.CKF_LOGIN_REQUIRED},
		prompt: func(PromptInfo) ([]byte, error) {
			return nil, errors.New("no credential")
		},
	}

	err := m.login(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error")
	}
}
