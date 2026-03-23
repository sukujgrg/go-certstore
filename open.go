package certstore

import (
	"context"
	"fmt"
)

// Open opens the configured identity backend.
//
// The context controls cancellation while the library resolves and initializes
// the requested backend. Passing nil is treated as context.Background().
//
// With no options, Open preserves the current platform-default behavior by
// opening the native backend for the current OS.
//
// When BackendAuto is selected explicitly or implicitly:
//   - native macOS and Windows backends are used by default
//   - any PKCS#11 option switches resolution to the PKCS#11 backend family,
//     which still requires an explicit module path
//   - any NSS option switches resolution to the NSS backend family, which
//     still requires both an explicit softokn3 module path and profile
//
// Use WithBackend to force a specific backend.
func Open(ctx context.Context, opts ...Option) (Store, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

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
				return nil, fmt.Errorf("%w: pkcs11 module path is required", ErrInvalidConfiguration)
			}
			return openPKCS11Store(ctx, cfg)
		}
		if hasNSSConfig(cfg) {
			if cfg.NSSModule == "" {
				return nil, fmt.Errorf("%w: nss module path is required", ErrInvalidConfiguration)
			}
			if cfg.NSSProfileDir == "" {
				return nil, fmt.Errorf("%w: nss profile directory is required", ErrInvalidConfiguration)
			}
			return openNSSStore(ctx, cfg)
		}
		return openNativeStore()
	case BackendPKCS11:
		return openPKCS11Store(ctx, cfg)
	case BackendNSS:
		return openNSSStore(ctx, cfg)
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

	if hasPKCS11Config(cfg) {
		if cfg.Backend != BackendAuto && cfg.Backend != BackendPKCS11 {
			return fmt.Errorf("%w: PKCS#11 options require backend %q or %q", ErrUnsupportedBackend, BackendAuto, BackendPKCS11)
		}
	}

	if hasNSSConfig(cfg) && cfg.Backend != BackendAuto && cfg.Backend != BackendNSS {
		return fmt.Errorf("%w: NSS options require backend %q or %q", ErrUnsupportedBackend, BackendAuto, BackendNSS)
	}

	if cfg.Backend == BackendAuto {
		if hasNSSConfig(cfg) && hasPKCS11Config(cfg) {
			return fmt.Errorf("%w: PKCS#11 and NSS options cannot be combined under backend %q", ErrUnsupportedBackend, BackendAuto)
		}
		if hasPKCS11Config(cfg) && cfg.PKCS11Module == "" {
			return fmt.Errorf("%w: pkcs11 module path is required", ErrInvalidConfiguration)
		}
		if hasNSSConfig(cfg) && cfg.NSSModule == "" {
			return fmt.Errorf("%w: nss module path is required", ErrInvalidConfiguration)
		}
		if hasNSSConfig(cfg) && cfg.NSSProfileDir == "" {
			return fmt.Errorf("%w: nss profile directory is required", ErrInvalidConfiguration)
		}
	}

	if cfg.Backend == BackendPKCS11 {
		if cfg.PKCS11Module == "" {
			return fmt.Errorf("%w: pkcs11 module path is required", ErrInvalidConfiguration)
		}
	}

	if cfg.Backend == BackendNSS {
		if hasPKCS11Config(cfg) {
			return fmt.Errorf("%w: PKCS#11 options require backend %q or %q", ErrUnsupportedBackend, BackendAuto, BackendPKCS11)
		}
		if cfg.NSSModule == "" {
			return fmt.Errorf("%w: nss module path is required", ErrInvalidConfiguration)
		}
		if cfg.NSSProfileDir == "" {
			return fmt.Errorf("%w: nss profile directory is required", ErrInvalidConfiguration)
		}
	}
	return nil
}

func hasPKCS11Config(cfg Options) bool {
	return cfg.PKCS11Module != "" || cfg.PKCS11TokenLabel != "" || cfg.PKCS11Slot != nil
}

func hasNSSConfig(cfg Options) bool {
	return cfg.NSSModule != "" || cfg.NSSProfileDir != ""
}
