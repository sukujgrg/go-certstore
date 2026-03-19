// Package certstore provides access to the system certificate store for
// client certificate authentication (mTLS). It exposes a read-only,
// interface-driven API for enumerating identities and signing with their
// private keys.
//
// Platform support:
//   - macOS: Keychain via Security.framework (CGo required)
//   - Windows: CertStore via CNG/CryptoAPI (CGo required)
//   - Linux: returns an error (no system cert store)
//
// Design inspired by github.com/github/smimesign/pkg/certstore.
package certstore

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// ErrUnsupportedHash is returned when the requested hash algorithm is not
// supported by the underlying platform signing implementation.
var ErrUnsupportedHash = errors.New("unsupported hash algorithm")

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
