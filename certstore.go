// Package certstore provides access to X.509 certificate identities from
// native stores and token/database backends. It exposes a read-only,
// interface-driven API for enumerating identities, retrieving certificate
// chains, and signing with their private keys.
//
// Scope:
//   - X.509 certificate identities backed by native stores or token/database backends
//   - certificate enumeration, selection, chain retrieval, and signing
//   - TLS client-certificate integration helpers
//
// Non-goals:
//   - SSH keys or SSH certificates
//   - generic secret storage
//   - profile, module, or token discovery heuristics
//   - prompting UX, GUI flows, or application-specific convenience policy
//
// The library intentionally keeps the application boundary explicit. Callers
// are expected to decide how to discover backends, select profiles or tokens,
// collect credentials, and present UX around those choices.
//
// One major use case is TLS client-certificate authentication (mTLS), but the
// package is not limited to TLS-specific workflows.
//
// Platform support:
//   - macOS: Keychain via Security.framework (CGo required)
//   - Windows: CertStore via CNG/CryptoAPI (CGo required)
//   - Any platform with CGo: PKCS#11 via explicit module path
//   - Any platform with CGo: NSS via explicit softokn3 module path and profile
//   - Linux native store: returns an error (no standard system client-cert store)
package certstore

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
)

// FilterFunc is a predicate for filtering certificates.
// Return true to include the identity in the result.
type FilterFunc func(*x509.Certificate) bool

// FilterIdentities opens the store, applies the filter to each identity's
// certificate, and returns matching identities. The caller must Close each
// returned identity when done. The store is closed before returning. The
// filter must be non-nil.
//
// The context controls cancellation while opening the store, listing
// identities, and loading their certificates. Passing nil is treated as
// context.Background().
func FilterIdentities(ctx context.Context, filter FilterFunc) ([]Identity, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	store, err := Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer store.Close()

	return filterStoreIdentities(ctx, store, filter)
}

func filterStoreIdentities(ctx context.Context, store Store, filter FilterFunc) ([]Identity, error) {
	if filter == nil {
		return nil, fmt.Errorf("%w: filter is required", ErrInvalidConfiguration)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfiguration)
	}

	idents, err := store.Identities(ctx)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}

	var matched []Identity
	for i, ident := range idents {
		if err := ctx.Err(); err != nil {
			closeOpenIdentities(idents)
			return nil, err
		}
		if ident == nil {
			continue
		}
		cert, err := ident.Certificate(ctx)
		if err != nil {
			ident.Close()
			idents[i] = nil
			continue
		}
		if filter(cert) {
			matched = append(matched, ident)
		} else {
			ident.Close()
			idents[i] = nil
		}
	}
	return matched, nil
}

// Store represents an open handle to a certificate-identity backend.
type Store interface {
	// Identities returns all identities (certificate + private key pairs)
	// available in the store. Passing nil is treated as context.Background().
	Identities(ctx context.Context) ([]Identity, error)

	// Close releases any resources held by the store.
	Close()
}

// Identity represents a single certificate and its associated private key.
type Identity interface {
	// Certificate returns the leaf certificate for this identity. Passing nil is
	// treated as context.Background().
	Certificate(ctx context.Context) (*x509.Certificate, error)

	// CertificateChain returns the full certificate chain for this identity,
	// starting with the leaf certificate. Passing nil is treated as
	// context.Background().
	CertificateChain(ctx context.Context) ([]*x509.Certificate, error)

	// Signer returns a crypto.Signer backed by this identity's private key.
	// Passing nil is treated as context.Background(). Backends that need late
	// re-authentication may retain this context because crypto.Signer.Sign does
	// not accept one.
	Signer(ctx context.Context) (crypto.Signer, error)

	// Close releases any resources held by this identity.
	Close()
}

// CloseableSigner is a crypto.Signer with explicit resource cleanup. Backends
// that hold native key handles may implement this so callers can release
// signer-owned resources deterministically instead of waiting for GC.
type CloseableSigner interface {
	crypto.Signer
	Close() error
}

// CloseSigner closes signer resources when the concrete signer supports
// explicit cleanup. This is the signer counterpart to Store.Close and
// Identity.Close.
//
// Callers that obtain a signer directly from Identity.Signer(ctx) should prefer to
// call CloseSigner when they are done so native handles, key references, or
// token sessions can be released promptly. It is a no-op for signers that do
// not implement CloseableSigner.
func CloseSigner(signer crypto.Signer) error {
	if closer, ok := signer.(CloseableSigner); ok {
		return closer.Close()
	}
	return nil
}

func closeOpenIdentities(idents []Identity) {
	for _, ident := range idents {
		if ident != nil {
			ident.Close()
		}
	}
}

// IdentityInfo provides optional metadata for backends that can surface a
// stable identity label or location. Not all Identity implementations expose
// this information.
//
// The IsHardwareBacked and RequiresLogin booleans are kept for broad
// compatibility. Callers that need to distinguish "no" from "unknown" should
// prefer IdentityCapabilityInfo when it is implemented.
type IdentityInfo interface {
	Label() string
	Backend() Backend
	KeyType() string
	IsHardwareBacked() bool
	RequiresLogin() bool
	URI() string
}

// CapabilityState describes whether an identity capability is present, absent,
// or simply not known for a given backend.
type CapabilityState int

const (
	// CapabilityUnknown means the backend cannot currently determine the value.
	CapabilityUnknown CapabilityState = iota
	// CapabilityNo means the capability is known to be absent.
	CapabilityNo
	// CapabilityYes means the capability is known to be present.
	CapabilityYes
)

// String returns a user-facing representation of the capability state.
func (s CapabilityState) String() string {
	switch s {
	case CapabilityNo:
		return "no"
	case CapabilityYes:
		return "yes"
	default:
		return "unknown"
	}
}

// IdentityCapabilityInfo provides tri-state capability metadata for identities
// where a backend can distinguish "no" from "not determined". When available,
// callers should prefer it over the boolean methods on IdentityInfo.
type IdentityCapabilityInfo interface {
	HardwareBackedState() CapabilityState
	LoginRequiredState() CapabilityState
}

// PKCS11IdentityInfo exposes backend-specific metadata for PKCS#11 identities.
// It is implemented only by the PKCS#11 backend. Native backends expose the
// generic IdentityInfo surface but do not provide token-specific fields.
type PKCS11IdentityInfo interface {
	IdentityInfo
	ModulePath() string
	SlotID() uint
	TokenLabel() string
	TokenSerial() string
}

// NSSIdentityInfo exposes backend-specific metadata for NSS identities. The
// NSS backend is configured explicitly with a softokn3 module path and an NSS
// profile directory; this interface surfaces those values back to the caller.
type NSSIdentityInfo interface {
	IdentityInfo
	ProfileDir() string
	ModulePath() string
	TokenLabel() string
	TokenSerial() string
}
