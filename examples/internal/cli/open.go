// Package cli holds shared flag helpers for the repository examples.
package cli

import (
	"fmt"
	"os"

	certstore "github.com/sukujgrg/go-certstore"
)

// OpenConfig is the common backend configuration accepted by the examples.
type OpenConfig struct {
	// Backend selects auto, pkcs11, or nss.
	Backend string
	// Module is the PKCS#11 module or NSS softokn3 path.
	Module string
	// Profile is the NSS profile directory.
	Profile string
	// Token is the PKCS#11 token label.
	Token string
	// PIN is the token or database credential.
	PIN string
}

// OpenOptions builds certstore.Open options from common example flags/env.
//
// PIN resolution order: OpenConfig.PIN, CERTSTORE_PIN, PKCS11_PIN.
func OpenOptions(cfg OpenConfig) ([]certstore.Option, error) {
	openOpts := make([]certstore.Option, 0, 4)
	switch cfg.Backend {
	case "auto":
	case "pkcs11":
		openOpts = append(openOpts, certstore.WithBackend(certstore.BackendPKCS11))
	case "nss":
		openOpts = append(openOpts, certstore.WithBackend(certstore.BackendNSS))
	default:
		return nil, fmt.Errorf("unsupported backend %q", cfg.Backend)
	}
	if cfg.Module != "" {
		if cfg.Backend == "nss" {
			openOpts = append(openOpts, certstore.WithNSSModule(cfg.Module))
		} else {
			openOpts = append(openOpts, certstore.WithPKCS11Module(cfg.Module))
		}
	}
	if cfg.Profile != "" {
		openOpts = append(openOpts, certstore.WithNSSProfileDir(cfg.Profile))
	}
	if cfg.Token != "" {
		openOpts = append(openOpts, certstore.WithPKCS11TokenLabel(cfg.Token))
	}
	pinValue := cfg.PIN
	if pinValue == "" {
		pinValue = os.Getenv("CERTSTORE_PIN")
	}
	if pinValue == "" {
		pinValue = os.Getenv("PKCS11_PIN")
	}
	if pinValue != "" {
		openOpts = append(openOpts, certstore.WithCredentialPrompt(func(certstore.PromptInfo) ([]byte, error) {
			return []byte(pinValue), nil
		}))
	}
	return openOpts, nil
}

// FindBackend sets FindIdentityOptions.Backend from an example -backend value.
func FindBackend(backend string) certstore.Backend {
	switch backend {
	case "pkcs11":
		return certstore.BackendPKCS11
	case "nss":
		return certstore.BackendNSS
	default:
		return ""
	}
}
