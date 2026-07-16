package cli

import (
	"testing"

	certstore "github.com/sukujgrg/go-certstore"
)

func TestOpenOptionsRejectsUnknownBackend(t *testing.T) {
	_, err := OpenOptions(OpenConfig{Backend: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestOpenOptionsPKCS11(t *testing.T) {
	opts, err := OpenOptions(OpenConfig{
		Backend: "pkcs11",
		Module:  "/tmp/module.so",
		Token:   "token",
		PIN:     "123456",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) == 0 {
		t.Fatal("expected options")
	}

	cfg := certstore.Options{Backend: certstore.BackendAuto}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.Backend != certstore.BackendPKCS11 {
		t.Fatalf("backend = %q, want %q", cfg.Backend, certstore.BackendPKCS11)
	}
	if cfg.PKCS11Module != "/tmp/module.so" {
		t.Fatalf("module = %q", cfg.PKCS11Module)
	}
	if cfg.PKCS11TokenLabel != "token" {
		t.Fatalf("token = %q", cfg.PKCS11TokenLabel)
	}
	if cfg.CredentialPrompt == nil {
		t.Fatal("expected credential prompt")
	}
	pin, err := cfg.CredentialPrompt(certstore.PromptInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if string(pin) != "123456" {
		t.Fatalf("pin = %q", pin)
	}
}

func TestOpenOptionsNSS(t *testing.T) {
	opts, err := OpenOptions(OpenConfig{
		Backend: "nss",
		Module:  "/tmp/libsoftokn3.so",
		Profile: "/tmp/nssdb",
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := certstore.Options{Backend: certstore.BackendAuto}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.Backend != certstore.BackendNSS {
		t.Fatalf("backend = %q, want %q", cfg.Backend, certstore.BackendNSS)
	}
	if cfg.NSSModule != "/tmp/libsoftokn3.so" {
		t.Fatalf("module = %q", cfg.NSSModule)
	}
	if cfg.NSSProfileDir != "/tmp/nssdb" {
		t.Fatalf("profile = %q", cfg.NSSProfileDir)
	}
}

func TestFindBackend(t *testing.T) {
	if got := FindBackend("pkcs11"); got != certstore.BackendPKCS11 {
		t.Fatalf("got %q", got)
	}
	if got := FindBackend("nss"); got != certstore.BackendNSS {
		t.Fatalf("got %q", got)
	}
	if got := FindBackend("auto"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestOpenOptionsAutoAllowsEmpty(t *testing.T) {
	opts, err := OpenOptions(OpenConfig{Backend: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 0 {
		t.Fatalf("expected no options, got %d", len(opts))
	}
}
