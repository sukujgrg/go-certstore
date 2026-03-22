//go:build darwin && cgo

// macOS Keychain implementation for gocertstore.
//
// Original inspiration: github.com/getvictor/mtls
// Design reference: github.com/github/smimesign/pkg/certstore

package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

// openNativeStore opens the macOS Keychain and returns a Store for enumerating identities.
func openNativeStore() (Store, error) {
	return &macStore{}, nil
}

// macStore implements Store for macOS Keychain.
type macStore struct{}

func (s *macStore) Identities() ([]Identity, error) {
	query := C.CFDictionaryCreateMutable(
		C.kCFAllocatorDefault, 0,
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks,
	)
	if query == 0 {
		return nil, errors.New("failed to create CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(unsafe.Pointer(query))) //nolint:govet

	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassIdentity))      //nolint:govet
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecReturnRef), unsafe.Pointer(C.kCFBooleanTrue))     //nolint:govet
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitAll)) //nolint:govet

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &result)
	if status == C.errSecItemNotFound {
		return nil, nil
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("SecItemCopyMatching failed: OSStatus %d", int32(status))
	}
	defer C.CFRelease(result)

	arr := C.CFArrayRef(result)
	n := int(C.CFArrayGetCount(arr))
	idents := make([]Identity, 0, n)
	for i := 0; i < n; i++ {
		ref := C.SecIdentityRef(C.CFArrayGetValueAtIndex(arr, C.CFIndex(i)))
		C.CFRetain(C.CFTypeRef(ref))
		idents = append(idents, &macIdentity{ref: ref})
	}
	return idents, nil
}

func (s *macStore) Close() {}

// macIdentity implements Identity for a macOS Keychain identity.
type macIdentity struct {
	ref     C.SecIdentityRef
	cert    *x509.Certificate
	certRaw []byte
	keyRef  C.SecKeyRef
}

func (id *macIdentity) Label() string {
	cert, err := id.Certificate()
	if err != nil {
		return ""
	}
	return identityLabelFromCert(cert)
}

func (id *macIdentity) Backend() Backend {
	return BackendDarwin
}

func (id *macIdentity) KeyType() string {
	cert, err := id.Certificate()
	if err != nil {
		return ""
	}
	return identityKeyTypeFromCert(cert)
}

func (id *macIdentity) IsHardwareBacked() bool {
	return false
}

func (id *macIdentity) RequiresLogin() bool {
	return false
}

func (id *macIdentity) HardwareBackedState() CapabilityState {
	return CapabilityUnknown
}

func (id *macIdentity) LoginRequiredState() CapabilityState {
	return CapabilityUnknown
}

func (id *macIdentity) URI() string {
	cert, err := id.Certificate()
	if err != nil {
		return ""
	}
	return identityURIFromCert(BackendDarwin, cert)
}

func (id *macIdentity) Certificate() (*x509.Certificate, error) {
	if id.cert != nil {
		return id.cert, nil
	}

	var certRef C.SecCertificateRef
	if status := C.SecIdentityCopyCertificate(id.ref, &certRef); status != C.errSecSuccess {
		return nil, fmt.Errorf("SecIdentityCopyCertificate failed: OSStatus %d", int32(status))
	}
	defer C.CFRelease(C.CFTypeRef(certRef))

	// Export to PEM then parse — simplest way to get DER bytes from Security.framework
	var pemData C.CFDataRef
	if status := C.SecItemExport(
		C.CFTypeRef(certRef), C.kSecFormatPEMSequence, C.kSecItemPemArmour, nil, &pemData,
	); status != C.errSecSuccess {
		return nil, fmt.Errorf("SecItemExport failed: OSStatus %d", int32(status))
	}
	defer C.CFRelease(C.CFTypeRef(pemData))

	raw := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(pemData)), C.int(C.CFDataGetLength(pemData)))
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block found in exported certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate: %w", err)
	}
	id.cert = cert
	id.certRaw = block.Bytes
	return cert, nil
}

func (id *macIdentity) CertificateChain() ([]*x509.Certificate, error) {
	cert, err := id.Certificate()
	if err != nil {
		return nil, err
	}

	var certRef C.SecCertificateRef
	if status := C.SecIdentityCopyCertificate(id.ref, &certRef); status != C.errSecSuccess {
		return nil, fmt.Errorf("SecIdentityCopyCertificate failed: OSStatus %d", int32(status))
	}
	defer C.CFRelease(C.CFTypeRef(certRef))

	certs := C.CFArrayCreateMutable(C.kCFAllocatorDefault, 1, &C.kCFTypeArrayCallBacks)
	C.CFArrayAppendValue(certs, unsafe.Pointer(certRef)) //nolint:govet
	defer C.CFRelease(C.CFTypeRef(certs))

	var policy C.SecPolicyRef = C.SecPolicyCreateBasicX509()
	defer C.CFRelease(C.CFTypeRef(policy))

	var trust C.SecTrustRef
	if status := C.SecTrustCreateWithCertificates(C.CFTypeRef(certs), C.CFTypeRef(policy), &trust); status != C.errSecSuccess {
		// Fall back to just the leaf cert
		return []*x509.Certificate{cert}, nil
	}
	defer C.CFRelease(C.CFTypeRef(trust))

	// Evaluate trust to build the chain.
	var cfErr C.CFErrorRef
	C.SecTrustEvaluateWithError(trust, &cfErr)
	// We don't care if evaluation fails (self-signed, expired, etc.) —
	// we just want the chain that was built.

	// Use SecTrustCopyCertificateChain (macOS 12+) instead of the deprecated
	// SecTrustGetCertificateAtIndex.
	chainArray := C.SecTrustCopyCertificateChain(trust)
	if chainArray == 0 {
		return []*x509.Certificate{cert}, nil
	}
	defer C.CFRelease(C.CFTypeRef(chainArray))

	chainLen := int(C.CFArrayGetCount(chainArray))
	chain := make([]*x509.Certificate, 0, chainLen)
	chain = append(chain, cert)

	for i := 1; i < chainLen; i++ {
		chainCertRef := C.SecCertificateRef(C.CFArrayGetValueAtIndex(chainArray, C.CFIndex(i)))
		if chainCertRef == 0 {
			continue
		}

		var chainPEM C.CFDataRef
		if status := C.SecItemExport(
			C.CFTypeRef(chainCertRef), C.kSecFormatPEMSequence, C.kSecItemPemArmour, nil, &chainPEM,
		); status != C.errSecSuccess {
			continue
		}
		raw := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(chainPEM)), C.int(C.CFDataGetLength(chainPEM)))
		C.CFRelease(C.CFTypeRef(chainPEM))

		block, _ := pem.Decode(raw)
		if block == nil {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		chain = append(chain, c)
	}
	return chain, nil
}

func (id *macIdentity) Signer() (crypto.Signer, error) {
	if id.keyRef == 0 {
		var keyRef C.SecKeyRef
		if status := C.SecIdentityCopyPrivateKey(id.ref, &keyRef); status != C.errSecSuccess {
			return nil, fmt.Errorf("SecIdentityCopyPrivateKey failed: OSStatus %d", int32(status))
		}
		if keyRef == 0 {
			return nil, errors.New("SecIdentityCopyPrivateKey returned nil private key")
		}
		id.keyRef = keyRef
	}

	cert, err := id.Certificate()
	if err != nil {
		return nil, err
	}

	// Retain the key so the signer owns its own reference, independent of
	// the identity's lifecycle. The caller may Close() the identity while
	// the signer is still in use (e.g. for TLS handshakes).
	if id.keyRef == 0 {
		return nil, errors.New("mac identity has no private key")
	}
	C.CFRetain(C.CFTypeRef(id.keyRef))

	signer := &macSigner{
		keyRef: id.keyRef,
		pub:    cert.PublicKey,
	}
	runtime.SetFinalizer(signer, (*macSigner).release)
	return signer, nil
}

func (id *macIdentity) Close() {
	if id.keyRef != 0 {
		C.CFRelease(C.CFTypeRef(id.keyRef))
		id.keyRef = 0
	}
	if id.ref != 0 {
		C.CFRelease(C.CFTypeRef(id.ref))
		id.ref = 0
	}
}

// macSigner implements crypto.Signer using Security.framework.
type macSigner struct {
	keyRef C.SecKeyRef
	pub    crypto.PublicKey
}

func (s *macSigner) release() {
	if s.keyRef != 0 {
		C.CFRelease(C.CFTypeRef(s.keyRef))
		s.keyRef = 0
	}
}

func (s *macSigner) Close() error {
	runtime.SetFinalizer(s, nil)
	s.release()
	return nil
}

func (s *macSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *macSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.keyRef == 0 {
		return nil, ErrClosed
	}
	algo, err := s.algorithm(opts)
	if err != nil {
		return nil, err
	}

	data := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&digest[0])), C.CFIndex(len(digest)))
	defer C.CFRelease(C.CFTypeRef(data))

	var cfErr C.CFErrorRef
	sig := C.SecKeyCreateSignature(s.keyRef, algo, C.CFDataRef(data), &cfErr)
	if cfErr != 0 {
		defer C.CFRelease(C.CFTypeRef(cfErr))
		return nil, fmt.Errorf("SecKeyCreateSignature failed")
	}
	defer C.CFRelease(C.CFTypeRef(sig))

	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(sig)), C.int(C.CFDataGetLength(sig))), nil
}

// algorithm maps (key type, hash, padding) to a SecKeyAlgorithm constant.
func (s *macSigner) algorithm(opts crypto.SignerOpts) (C.SecKeyAlgorithm, error) {
	hash := opts.HashFunc()
	_, isPSS := opts.(*rsa.PSSOptions)

	switch s.pub.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256, nil
		case crypto.SHA384:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384, nil
		case crypto.SHA512:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512, nil
		case crypto.SHA1:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA1, nil
		}
	default:
		if isPSS {
			// RSA-PSS (required by TLS 1.3)
			switch hash {
			case crypto.SHA256:
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256, nil
			case crypto.SHA384:
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384, nil
			case crypto.SHA512:
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512, nil
			}
		} else {
			// RSA PKCS#1 v1.5
			switch hash {
			case crypto.SHA256:
				return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256, nil
			case crypto.SHA384:
				return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384, nil
			case crypto.SHA512:
				return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512, nil
			case crypto.SHA1:
				return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1, nil
			}
		}
	}
	return 0, ErrUnsupportedHash
}
