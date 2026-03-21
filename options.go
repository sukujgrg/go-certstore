package certstore

// Backend identifies an identity source implementation.
type Backend string

const (
	// BackendAuto selects the default backend for the current platform.
	BackendAuto Backend = "auto"

	// BackendDarwin selects the macOS Keychain backend.
	BackendDarwin Backend = "darwin-keychain"

	// BackendWindows selects the Windows Cert Store backend.
	BackendWindows Backend = "windows-certstore"

	// BackendPKCS11 selects a PKCS#11 token/module backend.
	BackendPKCS11 Backend = "pkcs11"

	// BackendNSS selects an NSS profile/database backend.
	BackendNSS Backend = "nss"
)

// PromptInfo describes an interactive credential prompt for token-backed
// backends such as PKCS#11. The library surfaces this context to the caller's
// callback, but does not implement any prompting UX itself.
type PromptInfo struct {
	// Backend identifies the backend requesting credentials.
	Backend Backend
	// TokenLabel is the token label when the backend can determine it.
	TokenLabel string
	// SlotID is the numeric token slot when available.
	SlotID uint
	// Reason describes why credentials are being requested.
	Reason string
}

// Options configures backend selection and backend-specific parameters.
type Options struct {
	// Backend selects which backend to open. BackendAuto chooses the default
	// backend for the current platform unless backend-specific options imply a
	// different backend.
	Backend Backend

	// PKCS11Module is the module path to load when using the PKCS#11 backend.
	PKCS11Module string
	// PKCS11TokenLabel selects a PKCS#11 token by label.
	PKCS11TokenLabel string
	// PKCS11Slot selects a PKCS#11 token by numeric slot.
	PKCS11Slot *uint
	// PKCS11PINPrompt supplies credentials when a token login is required.
	PKCS11PINPrompt func(PromptInfo) (string, error)

	// NSSProfileDir selects an NSS profile/database directory. NSS support is
	// not implemented yet.
	NSSProfileDir string

	// UseP11Kit requests p11-kit-based PKCS#11 module discovery. This is not
	// implemented yet.
	UseP11Kit bool
}

// Option mutates Open options.
type Option func(*Options)

// WithBackend selects a specific backend instead of the platform default.
func WithBackend(backend Backend) Option {
	return func(opts *Options) {
		opts.Backend = backend
	}
}

// WithPKCS11Module configures the PKCS#11 module path.
func WithPKCS11Module(path string) Option {
	return func(opts *Options) {
		opts.PKCS11Module = path
	}
}

// WithPKCS11TokenLabel selects a PKCS#11 token by label. It may be combined
// with WithPKCS11Module, and may be combined with WithPKCS11Slot only when
// both refer to the same token.
func WithPKCS11TokenLabel(label string) Option {
	return func(opts *Options) {
		opts.PKCS11TokenLabel = label
	}
}

// WithPKCS11Slot selects a PKCS#11 slot id. It is an alternative to token-label
// selection for callers that already know the numeric slot.
func WithPKCS11Slot(slot uint) Option {
	return func(opts *Options) {
		slotCopy := slot
		opts.PKCS11Slot = &slotCopy
	}
}

// WithPKCS11PINPrompt configures the callback used when a PKCS#11 login is
// required. The callback is invoked lazily, only when the token requires
// credentials for enumeration or signing.
func WithPKCS11PINPrompt(prompt func(PromptInfo) (string, error)) Option {
	return func(opts *Options) {
		opts.PKCS11PINPrompt = prompt
	}
}

// WithNSSProfileDir configures the NSS profile directory.
func WithNSSProfileDir(dir string) Option {
	return func(opts *Options) {
		opts.NSSProfileDir = dir
	}
}

// WithP11Kit enables p11-kit-backed PKCS#11 module discovery.
//
// This option is reserved for future support and currently causes Open to
// return ErrUnsupportedBackend.
func WithP11Kit(enabled bool) Option {
	return func(opts *Options) {
		opts.UseP11Kit = enabled
	}
}
