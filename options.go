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
// backends such as PKCS#11.
type PromptInfo struct {
	Backend    Backend
	TokenLabel string
	SlotID     uint
	Reason     string
}

// Options configures backend selection and backend-specific parameters.
type Options struct {
	Backend Backend

	PKCS11Module     string
	PKCS11TokenLabel string
	PKCS11Slot       *uint
	PKCS11PINPrompt  func(PromptInfo) (string, error)

	NSSProfileDir string

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

// WithPKCS11TokenLabel selects a PKCS#11 token by label.
func WithPKCS11TokenLabel(label string) Option {
	return func(opts *Options) {
		opts.PKCS11TokenLabel = label
	}
}

// WithPKCS11Slot selects a PKCS#11 slot id.
func WithPKCS11Slot(slot uint) Option {
	return func(opts *Options) {
		slotCopy := slot
		opts.PKCS11Slot = &slotCopy
	}
}

// WithPKCS11PINPrompt configures the callback used when a PKCS#11 PIN is
// required.
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
func WithP11Kit(enabled bool) Option {
	return func(opts *Options) {
		opts.UseP11Kit = enabled
	}
}
