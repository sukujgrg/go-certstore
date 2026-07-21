// Package certstore provides read-only access to X.509 certificate and
// private-key identities in macOS Keychain, Windows Certificate Store,
// PKCS#11 tokens, and NSS databases.
//
// Start with [Open] to obtain a [Store]. A store enumerates [Identity] values
// that provide certificate chains and access to their private-key signers.
// Use [FindIdentity] or [FindIdentities] for common selection rules. Use
// [FilterIdentities] when selection requires a custom certificate predicate.
//
// For TLS client authentication, [NewClientCertificateSource] provides a
// reusable certificate callback with deterministic signer cleanup.
//
// # Scope
//
//   - X.509 certificate identities backed by native stores or token/database backends
//   - certificate enumeration, selection, chain retrieval, and signing
//   - TLS client-certificate integration helpers
//
// # Non-goals
//
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
// # Platform support
//
//   - macOS: Keychain via Security.framework (CGo required)
//   - Windows: CertStore via CNG/CryptoAPI (CGo required; CurrentUser/LocalMachine and store name selectable)
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

// FilterIdentities applies filter to each identity's certificate and returns
// matching identities. Non-matching identities are closed before returning.
// The caller must Close each returned identity when done, and is responsible
// for closing store.
//
// Unlike FindIdentities, this accepts an arbitrary certificate predicate
// instead of structured FindIdentityOptions. Prefer FindIdentities when the
// built-in filters are enough.
//
// The context controls cancellation while listing identities and loading their
// certificates. It must not be nil.
func FilterIdentities(ctx context.Context, store Store, filter FilterFunc) ([]Identity, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
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
	// available in the store. ctx must not be nil.
	Identities(ctx context.Context) ([]Identity, error)

	// Close releases any resources held by the store. It is idempotent and safe
	// to call concurrently with other Store methods.
	Close()
}

// Identity represents a single certificate and its associated private key.
type Identity interface {
	// Certificate returns the leaf certificate for this identity. ctx must not
	// be nil.
	Certificate(ctx context.Context) (*x509.Certificate, error)

	// CertificateChain returns the full certificate chain for this identity,
	// starting with the leaf certificate. ctx must not be nil.
	CertificateChain(ctx context.Context) ([]*x509.Certificate, error)

	// Signer returns a crypto.Signer backed by this identity's private key.
	// ctx must not be nil. Backends that need late
	// re-authentication may retain this context because crypto.Signer.Sign does
	// not accept one.
	Signer(ctx context.Context) (crypto.Signer, error)

	// Close releases any resources held by this identity. It is idempotent and
	// safe to call concurrently with other Identity methods. Operations that
	// require released native resources return ErrClosed; already-cached
	// certificate data and immutable metadata may remain available.
	Close()
}

// CloseableSigner is a crypto.Signer with explicit resource cleanup. Backends
// that hold native key handles may implement this so callers can release
// signer-owned resources deterministically instead of waiting for GC.
// Close is idempotent and safe to call concurrently with Sign.
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
// token sessions can be released promptly. It is a no-op when signer is nil or
// does not implement CloseableSigner.
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
	// Label returns the backend-provided identity label.
	Label() string
	// Backend returns the backend that owns the identity.
	Backend() Backend
	// KeyType returns the public-key algorithm, such as "RSA" or "ECDSA".
	KeyType() string
	// IsHardwareBacked reports whether the backend identifies the key as
	// hardware-backed. Use IdentityCapabilityInfo when an unknown state must be
	// distinguished from false.
	IsHardwareBacked() bool
	// RequiresLogin reports whether the backend identifies the token or store as
	// requiring login. Use IdentityCapabilityInfo when an unknown state must be
	// distinguished from false.
	RequiresLogin() bool
	// URI returns a backend-specific stable identifier for the identity.
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
	// HardwareBackedState returns CapabilityYes if the key is hardware-backed,
	// CapabilityNo if it is not, or CapabilityUnknown if the backend cannot
	// determine the state.
	HardwareBackedState() CapabilityState
	// LoginRequiredState returns CapabilityYes if the token or store requires
	// login, CapabilityNo if it does not, or CapabilityUnknown if the backend
	// cannot determine the state.
	LoginRequiredState() CapabilityState
}

// PKCS11IdentityInfo exposes backend-specific metadata for PKCS#11 identities.
// It is implemented only by the PKCS#11 backend. Native backends expose the
// generic IdentityInfo surface but do not provide token-specific fields.
type PKCS11IdentityInfo interface {
	IdentityInfo
	// ModulePath returns the configured PKCS#11 module path.
	ModulePath() string
	// SlotID returns the numeric PKCS#11 slot identifier.
	SlotID() uint
	// TokenLabel returns the token label without surrounding padding.
	TokenLabel() string
	// TokenSerial returns the token serial number without surrounding padding.
	TokenSerial() string
}

// NSSIdentityInfo exposes backend-specific metadata for NSS identities. The
// NSS backend is configured explicitly with a softokn3 module path and an NSS
// profile directory; this interface surfaces those values back to the caller.
type NSSIdentityInfo interface {
	IdentityInfo
	// ProfileDir returns the configured NSS profile directory.
	ProfileDir() string
	// ModulePath returns the configured NSS softokn3 module path.
	ModulePath() string
	// TokenLabel returns the NSS token label without surrounding padding.
	TokenLabel() string
	// TokenSerial returns the NSS token serial number without surrounding padding.
	TokenSerial() string
}
