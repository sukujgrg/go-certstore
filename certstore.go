// Package certstore provides access to the system certificate store for
// client certificate authentication (mTLS). It exposes a read-only,
// interface-driven API for enumerating identities and signing with their
// private keys.
//
// Platform support:
//   - macOS: Keychain via Security.framework (CGo required)
//   - Windows: CertStore via CNG/CryptoAPI (CGo required)
//   - Any platform with CGo: PKCS#11 via explicit module path
//   - Linux native store: returns an error (no standard system client-cert store)
package certstore

import (
	"crypto"
	"crypto/x509"
)

// FilterFunc is a predicate for filtering certificates.
// Return true to include the identity in the result.
type FilterFunc func(*x509.Certificate) bool

// FilterIdentities opens the store, applies the filter to each identity's
// certificate, and returns matching identities. The caller must Close each
// returned identity when done. The store is closed before returning.
func FilterIdentities(filter FilterFunc) ([]Identity, error) {
	store, err := Open()
	if err != nil {
		return nil, err
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		return nil, err
	}

	var matched []Identity
	for _, ident := range idents {
		cert, err := ident.Certificate()
		if err != nil {
			ident.Close()
			continue
		}
		if filter(cert) {
			matched = append(matched, ident)
		} else {
			ident.Close()
		}
	}
	return matched, nil
}

// Store represents an open handle to the system certificate store.
type Store interface {
	// Identities returns all identities (certificate + private key pairs)
	// available in the store.
	Identities() ([]Identity, error)

	// Close releases any resources held by the store.
	Close()
}

// Identity represents a single certificate and its associated private key.
type Identity interface {
	// Certificate returns the leaf certificate for this identity.
	Certificate() (*x509.Certificate, error)

	// CertificateChain returns the full certificate chain for this identity,
	// starting with the leaf certificate.
	CertificateChain() ([]*x509.Certificate, error)

	// Signer returns a crypto.Signer backed by this identity's private key.
	Signer() (crypto.Signer, error)

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
// explicit cleanup. It is a no-op for signers that do not implement
// CloseableSigner.
func CloseSigner(signer crypto.Signer) error {
	if closer, ok := signer.(CloseableSigner); ok {
		return closer.Close()
	}
	return nil
}

// IdentityInfo provides optional metadata for backends that can surface a
// stable identity label or location. Not all Identity implementations expose
// this information.
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
	CapabilityUnknown CapabilityState = iota
	CapabilityNo
	CapabilityYes
)

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
// where a backend can distinguish "no" from "not determined".
type IdentityCapabilityInfo interface {
	HardwareBackedState() CapabilityState
	LoginRequiredState() CapabilityState
}

// PKCS11IdentityInfo exposes backend-specific metadata for PKCS#11 identities.
// It is implemented only by the PKCS#11 backend.
type PKCS11IdentityInfo interface {
	IdentityInfo
	ModulePath() string
	SlotID() uint
	TokenLabel() string
	TokenSerial() string
}
