// Package pkcs11 is the repository's low-level PKCS#11 adapter boundary.
//
// This package wraps github.com/miekg/pkcs11 so that the rest of go-certstore
// depends on a small package-owned surface, while the concrete PKCS#11 binding
// sits behind a single implementation owned by this package.
//
// Today that implementation is backed by github.com/miekg/pkcs11. The point of
// this package is not to replace that dependency immediately; it is to keep the
// dependency from leaking through the rest of the repository and to make any
// future replacement a local change inside internal/pkcs11.
//
// The package-owned types intentionally store encoded PKCS#11 byte values rather
// than exposing upstream structs directly. Constructors and translation helpers
// copy those byte slices so callers do not accidentally share mutable buffers
// with the upstream binding.
//
// The surface is intentionally narrower than the full upstream binding: it only
// exposes the PKCS#11 pieces go-certstore currently needs for certificate/key
// enumeration and signing.
package pkcs11
