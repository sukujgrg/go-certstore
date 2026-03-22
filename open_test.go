package certstore

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateOptions(t *testing.T) {
	t.Run("auto requires module when pkcs11 options are set", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:          BackendAuto,
			PKCS11TokenLabel: "YubiKey",
		})
		if !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "pkcs11 module path is required") {
			t.Fatalf("expected missing module error, got %v", err)
		}
	})

	t.Run("pkcs11 backend requires module", func(t *testing.T) {
		err := validateOptions(Options{
			Backend: BackendPKCS11,
		})
		if !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "pkcs11 module path is required") {
			t.Fatalf("expected missing module error, got %v", err)
		}
	})

	t.Run("native backend rejects pkcs11 options", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:      BackendDarwin,
			PKCS11Module: "/tmp/module.so",
		})
		if err == nil {
			t.Fatal("expected backend mismatch error")
		}
	})
}

func TestHasPKCS11Config(t *testing.T) {
	if hasPKCS11Config(Options{}) {
		t.Fatal("expected empty options to report no pkcs11 config")
	}

	slot := uint(7)
	if !hasPKCS11Config(Options{PKCS11Slot: &slot}) {
		t.Fatal("expected slot selection to count as pkcs11 config")
	}
}

func TestValidateOptionsAdditionalCases(t *testing.T) {
	t.Run("unknown backend", func(t *testing.T) {
		err := validateOptions(Options{Backend: Backend("bogus")})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("nss with non-nss backend", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:       BackendPKCS11,
			PKCS11Module:  "/tmp/module.so",
			NSSModule:     "/tmp/libsoftokn3.so",
			NSSProfileDir: "/tmp/nss",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("p11kit unsupported", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:   BackendPKCS11,
			UseP11Kit: true,
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("nss backend requires module", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:       BackendNSS,
			NSSProfileDir: "/tmp/nss",
		})
		if !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "nss module path is required") {
			t.Fatalf("expected missing module error, got %v", err)
		}
	})

	t.Run("nss backend requires profile", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:   BackendNSS,
			NSSModule: "/tmp/libsoftokn3.so",
		})
		if !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "nss profile directory is required") {
			t.Fatalf("expected missing profile error, got %v", err)
		}
	})

	t.Run("auto rejects mixed nss and pkcs11 config", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:       BackendAuto,
			PKCS11Module:  "/tmp/module.so",
			NSSModule:     "/tmp/libsoftokn3.so",
			NSSProfileDir: "/tmp/nss",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestHasNSSConfig(t *testing.T) {
	if hasNSSConfig(Options{}) {
		t.Fatal("expected empty options to report no nss config")
	}

	if !hasNSSConfig(Options{NSSProfileDir: "/tmp/nss"}) {
		t.Fatal("expected nss profile to count as nss config")
	}
}
