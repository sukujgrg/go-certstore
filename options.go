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

	// BackendNSS selects an NSS profile/database backend via an explicit
	// softokn3 module path and profile directory.
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

// CredentialPrompt is called when a token or database backend needs
// credentials to continue. The returned buffer is treated as secret material
// and is wiped by the library after each login attempt it performs. Some
// underlying dependencies still expose string-based APIs, so this reduces
// avoidable copies in this package but is not a high-assurance secret-memory
// guarantee.
type CredentialPrompt func(PromptInfo) ([]byte, error)

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
	// CredentialPrompt supplies credentials when a token or database login is
	// required. The returned buffer is wiped by the library after each login
	// attempt it performs, but underlying dependencies may still make their own
	// transient copies.
	CredentialPrompt CredentialPrompt

	// NSSModule is the NSS softokn3 PKCS#11 module path to load when using the
	// NSS backend.
	NSSModule string
	// NSSProfileDir selects an NSS profile/database directory. The library uses
	// this profile explicitly and does not try to discover browser profiles.
	NSSProfileDir string
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

// WithCredentialPrompt configures the callback used when a token-backed or
// database-backed backend such as PKCS#11 or NSS requires credentials.
// The callback is invoked lazily, only when the backend requires credentials
// for enumeration or signing. The returned buffer is wiped by the library
// after each login attempt, so callers should return a dedicated secret buffer
// instead of a shared slice they intend to keep using. This reduces avoidable
// copies in this package, but underlying dependencies may still copy the
// credential internally.
func WithCredentialPrompt(prompt CredentialPrompt) Option {
	return func(opts *Options) {
		opts.CredentialPrompt = prompt
	}
}

// WithNSSModule configures the NSS softokn3 PKCS#11 module path.
func WithNSSModule(path string) Option {
	return func(opts *Options) {
		opts.NSSModule = path
	}
}

// WithNSSProfileDir configures the NSS profile/database directory.
func WithNSSProfileDir(dir string) Option {
	return func(opts *Options) {
		opts.NSSProfileDir = dir
	}
}
