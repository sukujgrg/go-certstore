package certstore

import "testing"

func TestValidateOptions(t *testing.T) {
	t.Run("auto requires module when pkcs11 options are set", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:          BackendAuto,
			PKCS11TokenLabel: "YubiKey",
		})
		if err == nil || err.Error() != "pkcs11 module path is required" {
			t.Fatalf("expected missing module error, got %v", err)
		}
	})

	t.Run("pkcs11 backend requires module", func(t *testing.T) {
		err := validateOptions(Options{
			Backend: BackendPKCS11,
		})
		if err == nil || err.Error() != "pkcs11 module path is required" {
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
