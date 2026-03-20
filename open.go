package certstore

import (
	"fmt"
)

// Open opens the configured identity backend. Calling Open() with no options
// preserves the current platform-default behavior.
func Open(opts ...Option) (Store, error) {
	cfg := Options{Backend: BackendAuto}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.Backend == "" {
		cfg.Backend = BackendAuto
	}

	if err := validateOptions(cfg); err != nil {
		return nil, err
	}

	switch cfg.Backend {
	case BackendAuto:
		if hasPKCS11Config(cfg) {
			if cfg.PKCS11Module == "" {
				return nil, fmt.Errorf("pkcs11 module path is required")
			}
			return openPKCS11Store(cfg)
		}
		if cfg.UseP11Kit {
			return nil, fmt.Errorf("%w: p11-kit discovery is not implemented yet", ErrUnsupportedBackend)
		}
		if cfg.NSSProfileDir != "" {
			return nil, fmt.Errorf("%w: backend %q is not implemented yet", ErrUnsupportedBackend, BackendNSS)
		}
		return openNativeStore()
	case BackendPKCS11:
		return openPKCS11Store(cfg)
	case BackendNSS:
		return nil, fmt.Errorf("%w: backend %q is not implemented yet", ErrUnsupportedBackend, BackendNSS)
	}

	if native := currentNativeBackend(); native != "" && cfg.Backend == native {
		return openNativeStore()
	}

	return nil, fmt.Errorf("%w: backend %q is not available on this platform", ErrUnsupportedBackend, cfg.Backend)
}

func validateOptions(cfg Options) error {
	switch cfg.Backend {
	case "", BackendAuto, BackendDarwin, BackendWindows, BackendPKCS11, BackendNSS:
	default:
		return fmt.Errorf("%w: backend %q is unknown", ErrUnsupportedBackend, cfg.Backend)
	}

	if hasPKCS11Config(cfg) || cfg.UseP11Kit {
		if cfg.Backend != BackendAuto && cfg.Backend != BackendPKCS11 {
			return fmt.Errorf("%w: PKCS#11 options require backend %q or %q", ErrUnsupportedBackend, BackendAuto, BackendPKCS11)
		}
	}

	if cfg.NSSProfileDir != "" && cfg.Backend != BackendAuto && cfg.Backend != BackendNSS {
		return fmt.Errorf("%w: NSS options require backend %q or %q", ErrUnsupportedBackend, BackendAuto, BackendNSS)
	}

	if cfg.Backend == BackendAuto {
		if cfg.UseP11Kit {
			return fmt.Errorf("%w: p11-kit discovery is not implemented yet", ErrUnsupportedBackend)
		}
		if hasPKCS11Config(cfg) && cfg.PKCS11Module == "" {
			return fmt.Errorf("pkcs11 module path is required")
		}
		if cfg.NSSProfileDir != "" {
			return fmt.Errorf("%w: backend %q is not implemented yet", ErrUnsupportedBackend, BackendNSS)
		}
	}

	if cfg.Backend == BackendPKCS11 {
		if cfg.UseP11Kit {
			return fmt.Errorf("%w: p11-kit discovery is not implemented yet", ErrUnsupportedBackend)
		}
		if cfg.PKCS11Module == "" {
			return fmt.Errorf("pkcs11 module path is required")
		}
	}

	if cfg.Backend == BackendNSS {
		return fmt.Errorf("%w: backend %q is not implemented yet", ErrUnsupportedBackend, BackendNSS)
	}
	return nil
}

func hasPKCS11Config(cfg Options) bool {
	return cfg.PKCS11Module != "" || cfg.PKCS11TokenLabel != "" || cfg.PKCS11PINPrompt != nil || cfg.PKCS11Slot != nil
}
