package certstore

import "testing"

func TestOptionSetters(t *testing.T) {
	var opts Options

	WithBackend(BackendPKCS11)(&opts)
	WithPKCS11Module("/tmp/module.so")(&opts)
	WithPKCS11TokenLabel("token-label")(&opts)
	WithPKCS11Slot(7)(&opts)
	WithPKCS11PINPrompt(func(PromptInfo) (string, error) { return "1234", nil })(&opts)
	WithNSSProfileDir("/tmp/nss-profile")(&opts)
	WithP11Kit(true)(&opts)

	if opts.Backend != BackendPKCS11 {
		t.Fatalf("Backend = %q", opts.Backend)
	}
	if opts.PKCS11Module != "/tmp/module.so" {
		t.Fatalf("PKCS11Module = %q", opts.PKCS11Module)
	}
	if opts.PKCS11TokenLabel != "token-label" {
		t.Fatalf("PKCS11TokenLabel = %q", opts.PKCS11TokenLabel)
	}
	if opts.PKCS11Slot == nil || *opts.PKCS11Slot != 7 {
		t.Fatalf("PKCS11Slot = %v", opts.PKCS11Slot)
	}
	if opts.PKCS11PINPrompt == nil {
		t.Fatal("PKCS11PINPrompt is nil")
	}
	if opts.NSSProfileDir != "/tmp/nss-profile" {
		t.Fatalf("NSSProfileDir = %q", opts.NSSProfileDir)
	}
	if !opts.UseP11Kit {
		t.Fatal("UseP11Kit = false")
	}
}
