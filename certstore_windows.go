//go:build windows && cgo

// Windows CertStore implementation for go-certstore.
//
// Based on github.com/github/smimesign/pkg/certstore (Windows implementation).
// Uses CGo with CNG/CryptoAPI for robust certificate and signing support.

package certstore

/*
#cgo windows LDFLAGS: -lcrypt32 -lncrypt
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>

// FormatMessage wrapper for Go-friendly error strings.
static char* formatError(DWORD errCode) {
    char* msg = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msg,
        0,
        NULL
    );
    return msg;
}

// BCRYPT_*_ALGORITHM are wide string macros (L"...") which cgo cannot access
// directly. Expose them as function calls instead.
static LPCWSTR getBcryptSHA1Algorithm()   { return BCRYPT_SHA1_ALGORITHM; }
static LPCWSTR getBcryptSHA256Algorithm() { return BCRYPT_SHA256_ALGORITHM; }
static LPCWSTR getBcryptSHA384Algorithm() { return BCRYPT_SHA384_ALGORITHM; }
static LPCWSTR getBcryptSHA512Algorithm() { return BCRYPT_SHA512_ALGORITHM; }
*/
import "C"

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"unsafe"
)

// openNativeStore opens the Windows "MY" certificate store for the current user.
func openNativeStore() (Store, error) {
	storeName := C.CString("MY")
	defer C.free(unsafe.Pointer(storeName))

	h := C.CertOpenSystemStoreA(0, storeName)
	if h == nil {
		return nil, lastError("CertOpenSystemStore")
	}
	return &winStore{h: h}, nil
}

type winStore struct {
	h C.HCERTSTORE
}

func (s *winStore) Identities(ctx context.Context) ([]Identity, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var idents []Identity

	// Use CertFindChainInStore for proper chain-aware enumeration.
	var chainPara C.CERT_CHAIN_FIND_BY_ISSUER_PARA
	chainPara.cbSize = C.DWORD(unsafe.Sizeof(chainPara))

	var prev *C.CERT_CHAIN_CONTEXT
	for {
		chainCtx := C.CertFindChainInStore(
			s.h,
			C.X509_ASN_ENCODING|C.PKCS_7_ASN_ENCODING,
			0,
			C.CERT_CHAIN_FIND_BY_ISSUER,
			unsafe.Pointer(&chainPara),
			(*C.CERT_CHAIN_CONTEXT)(unsafe.Pointer(prev)),
		)
		if chainCtx == nil {
			break
		}
		if err := ctx.Err(); err != nil {
			C.CertFreeCertificateChain(chainCtx)
			closeOpenIdentities(idents)
			return nil, err
		}
		prev = chainCtx

		if chainCtx.cChain < 1 {
			continue
		}

		// Get the first (and usually only) simple chain.
		simpleChain := *chainCtx.rgpChain
		if simpleChain.cElement < 1 {
			continue
		}

		// The first element is the end-entity cert.
		elements := unsafe.Slice(simpleChain.rgpElement, simpleChain.cElement)
		leafElement := elements[0]
		certCtx := leafElement.pCertContext

		// Duplicate the cert context so it survives after we free the chain.
		dup := C.CertDuplicateCertificateContext(certCtx)
		if dup == nil {
			continue
		}

		// Parse chain certificates eagerly because CertFindChainInStore
		// frees the previous chain context on the next call.
		var chainCerts []*x509.Certificate
		for _, elem := range elements {
			der := C.GoBytes(unsafe.Pointer(elem.pCertContext.pbCertEncoded), C.int(elem.pCertContext.cbCertEncoded))
			c, parseErr := x509.ParseCertificate(der)
			if parseErr != nil {
				continue
			}
			chainCerts = append(chainCerts, c)
		}

		idents = append(idents, &winIdentity{
			ctx:        dup,
			chainCerts: chainCerts,
		})
	}

	return idents, nil
}

func (s *winStore) Close() {
	if s.h != nil {
		C.CertCloseStore(s.h, 0)
		s.h = nil
	}
}

type winIdentity struct {
	ctx        *C.CERT_CONTEXT
	chainCerts []*x509.Certificate // parsed eagerly; see Identities()
	certMu     sync.Mutex
	cert       *x509.Certificate
}

func (id *winIdentity) Label() string {
	cert, err := id.Certificate(context.Background())
	if err != nil {
		return ""
	}
	return identityLabelFromCert(cert)
}

func (id *winIdentity) Backend() Backend {
	return BackendWindows
}

func (id *winIdentity) KeyType() string {
	cert, err := id.Certificate(context.Background())
	if err != nil {
		return ""
	}
	return identityKeyTypeFromCert(cert)
}

func (id *winIdentity) IsHardwareBacked() bool {
	return false
}

func (id *winIdentity) RequiresLogin() bool {
	return false
}

func (id *winIdentity) HardwareBackedState() CapabilityState {
	return CapabilityUnknown
}

func (id *winIdentity) LoginRequiredState() CapabilityState {
	return CapabilityUnknown
}

func (id *winIdentity) URI() string {
	cert, err := id.Certificate(context.Background())
	if err != nil {
		return ""
	}
	return identityURIFromCert(BackendWindows, cert)
}

func (id *winIdentity) Certificate(ctx context.Context) (*x509.Certificate, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id.certMu.Lock()
	defer id.certMu.Unlock()
	if id.cert != nil {
		return id.cert, nil
	}

	der := C.GoBytes(unsafe.Pointer(id.ctx.pbCertEncoded), C.int(id.ctx.cbCertEncoded))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate: %w", err)
	}
	id.cert = cert
	return cert, nil
}

func (id *winIdentity) CertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(id.chainCerts) > 0 {
		return id.chainCerts, nil
	}
	cert, err := id.Certificate(ctx)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

func (id *winIdentity) Signer(ctx context.Context) (crypto.Signer, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cert, err := id.Certificate(ctx)
	if err != nil {
		return nil, fmt.Errorf("load Windows certificate for signer: %w", err)
	}

	var (
		keyHandle  C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
		keySpec    C.DWORD
		callerFree C.BOOL
	)

	// Prefer CNG (NCrypt) keys but fall back to CryptoAPI (legacy).
	ok := C.CryptAcquireCertificatePrivateKey(
		id.ctx,
		C.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|C.CRYPT_ACQUIRE_SILENT_FLAG,
		nil,
		&keyHandle,
		&keySpec,
		&callerFree,
	)
	if ok == 0 {
		return nil, fmt.Errorf("create Windows signer: %w", lastError("CryptAcquireCertificatePrivateKey"))
	}

	isNCrypt := keySpec == C.CERT_NCRYPT_KEY_SPEC
	signer := &winSigner{
		pub:        cert.PublicKey,
		keyHandle:  keyHandle,
		isNCrypt:   isNCrypt,
		callerFree: callerFree != 0,
	}
	if signer.callerFree {
		runtime.SetFinalizer(signer, (*winSigner).release)
	}
	return signer, nil
}

func (id *winIdentity) Close() {
	if id.ctx != nil {
		C.CertFreeCertificateContext(id.ctx)
		id.ctx = nil
	}
}

type winSigner struct {
	pub        crypto.PublicKey
	keyHandle  C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
	isNCrypt   bool
	callerFree bool
}

func (s *winSigner) release() {
	if !s.callerFree || s.keyHandle == 0 {
		return
	}
	if s.isNCrypt {
		C.NCryptFreeObject(C.NCRYPT_HANDLE(s.keyHandle))
	} else {
		C.CryptReleaseContext(C.HCRYPTPROV(s.keyHandle), 0)
	}
	s.keyHandle = 0
}

func (s *winSigner) Close() error {
	runtime.SetFinalizer(s, nil)
	s.release()
	return nil
}

func (s *winSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *winSigner) supportedSignatureAlgorithms() []tls.SignatureScheme {
	if !s.isNCrypt {
		if _, ok := s.pub.(*rsa.PublicKey); ok {
			return []tls.SignatureScheme{
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}
		}
		return nil
	}
	return supportedSignatureAlgorithmsForPublicKey(s.pub)
}

func (s *winSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.keyHandle == 0 {
		return nil, ErrClosed
	}
	if s.isNCrypt {
		return s.signNCrypt(digest, opts)
	}
	return s.signCryptoAPI(digest, opts)
}

// signNCrypt signs using CNG (NCrypt).
func (s *winSigner) signNCrypt(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash, err := signerHash(opts)
	if err != nil {
		return nil, err
	}
	pss, isPSS := opts.(*rsa.PSSOptions)

	var paddingInfo unsafe.Pointer
	var flags C.DWORD = C.NCRYPT_SILENT_FLAG

	switch s.pub.(type) {
	case *ecdsa.PublicKey:
		// No padding for ECDSA
	default:
		algID, err := ncryptAlgorithmID(hash)
		if err != nil {
			return nil, err
		}
		if isPSS {
			rsaPub, ok := s.pub.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("%w: RSA-PSS requires an RSA public key", ErrMechanismUnsupported)
			}
			saltLength, err := normalizePSSSaltLength(rsaPub, hash, pss.SaltLength)
			if err != nil {
				return nil, err
			}
			// RSA-PSS padding (required by TLS 1.3)
			padding := C.BCRYPT_PSS_PADDING_INFO{
				pszAlgId: algID,
				cbSalt:   C.ULONG(saltLength),
			}
			paddingInfo = unsafe.Pointer(&padding)
			flags |= C.BCRYPT_PAD_PSS
		} else {
			// RSA PKCS#1 v1.5 padding
			padding := C.BCRYPT_PKCS1_PADDING_INFO{
				pszAlgId: algID,
			}
			paddingInfo = unsafe.Pointer(&padding)
			flags |= C.BCRYPT_PAD_PKCS1
		}
	}

	// First call: get signature size.
	var sigLen C.DWORD
	status := C.NCryptSignHash(
		C.NCRYPT_KEY_HANDLE(s.keyHandle),
		paddingInfo,
		(*C.BYTE)(byteSlicePtr(digest)),
		C.DWORD(len(digest)),
		nil,
		0,
		&sigLen,
		flags,
	)
	if status != 0 {
		return nil, fmt.Errorf("NCryptSignHash (size): SECURITY_STATUS 0x%08x", uint32(status))
	}

	// Second call: produce the signature.
	sig := make([]byte, sigLen)
	status = C.NCryptSignHash(
		C.NCRYPT_KEY_HANDLE(s.keyHandle),
		paddingInfo,
		(*C.BYTE)(byteSlicePtr(digest)),
		C.DWORD(len(digest)),
		(*C.BYTE)(byteSlicePtr(sig)),
		sigLen,
		&sigLen,
		flags,
	)
	if status != 0 {
		return nil, fmt.Errorf("NCryptSignHash (sign): SECURITY_STATUS 0x%08x", uint32(status))
	}
	sig = sig[:sigLen]

	// CNG returns raw ECDSA signatures (r || s); Go expects ASN.1 DER.
	if ecPub, ok := s.pub.(*ecdsa.PublicKey); ok {
		return ecdsaRawToASN1(sig, ecPub)
	}

	return sig, nil
}

// signCryptoAPI signs using the legacy CryptoAPI.
func (s *winSigner) signCryptoAPI(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
		return nil, errors.New("CryptoAPI private keys do not support RSA-PSS signing")
	}
	if _, ok := s.pub.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("CryptoAPI private keys do not support %T", s.pub)
	}

	hash, err := signerHash(opts)
	if err != nil {
		return nil, err
	}

	algID, err := cryptoAPIAlgID(hash)
	if err != nil {
		return nil, err
	}

	var cryptHash C.HCRYPTHASH
	if ok := C.CryptCreateHash(C.HCRYPTPROV(s.keyHandle), algID, 0, 0, &cryptHash); ok == 0 {
		return nil, lastError("CryptCreateHash")
	}
	defer C.CryptDestroyHash(cryptHash)

	if ok := C.CryptSetHashParam(cryptHash, C.HP_HASHVAL, (*C.BYTE)(byteSlicePtr(digest)), 0); ok == 0 {
		return nil, lastError("CryptSetHashParam")
	}

	// Get signature size.
	var sigLen C.DWORD
	if ok := C.CryptSignHashW(cryptHash, C.AT_KEYEXCHANGE, nil, 0, nil, &sigLen); ok == 0 {
		if ok = C.CryptSignHashW(cryptHash, C.AT_SIGNATURE, nil, 0, nil, &sigLen); ok == 0 {
			return nil, lastError("CryptSignHash (size)")
		}
	}

	sig := make([]byte, sigLen)
	if ok := C.CryptSignHashW(cryptHash, C.AT_KEYEXCHANGE, nil, 0, (*C.BYTE)(byteSlicePtr(sig)), &sigLen); ok == 0 {
		if ok = C.CryptSignHashW(cryptHash, C.AT_SIGNATURE, nil, 0, (*C.BYTE)(byteSlicePtr(sig)), &sigLen); ok == 0 {
			return nil, lastError("CryptSignHash")
		}
	}
	sig = sig[:sigLen]

	// CryptoAPI returns the signature in little-endian; reverse it.
	for i, j := 0, len(sig)-1; i < j; i, j = i+1, j-1 {
		sig[i], sig[j] = sig[j], sig[i]
	}

	return sig, nil
}

// ncryptAlgorithmID maps a crypto.Hash to the CNG algorithm identifier string.
func ncryptAlgorithmID(hash crypto.Hash) (C.LPCWSTR, error) {
	switch hash {
	case crypto.SHA1:
		return C.getBcryptSHA1Algorithm(), nil
	case crypto.SHA256:
		return C.getBcryptSHA256Algorithm(), nil
	case crypto.SHA384:
		return C.getBcryptSHA384Algorithm(), nil
	case crypto.SHA512:
		return C.getBcryptSHA512Algorithm(), nil
	default:
		return nil, ErrUnsupportedHash
	}
}

// cryptoAPIAlgID maps a crypto.Hash to a CryptoAPI ALG_ID.
func cryptoAPIAlgID(hash crypto.Hash) (C.ALG_ID, error) {
	switch hash {
	case crypto.SHA1:
		return C.CALG_SHA1, nil
	case crypto.SHA256:
		return C.CALG_SHA_256, nil
	case crypto.SHA384:
		return C.CALG_SHA_384, nil
	case crypto.SHA512:
		return C.CALG_SHA_512, nil
	default:
		return 0, ErrUnsupportedHash
	}
}

// lastError returns a Go error from GetLastError with a formatted message.
func lastError(context string) error {
	code := C.GetLastError()
	msg := C.formatError(code)
	if msg != nil {
		defer C.LocalFree(C.HLOCAL(unsafe.Pointer(msg)))
		return fmt.Errorf("%s: %s (0x%08x)", context, C.GoString(msg), uint32(code))
	}
	return fmt.Errorf("%s: error 0x%08x", context, uint32(code))
}

// suppress unused import warnings
var _ = elliptic.P256
var _ = errors.New
