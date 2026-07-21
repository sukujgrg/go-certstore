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

// BCRYPT_*_ALGORITHM are wide string macros (L"...") which cgo cannot access
// directly. Expose them as function calls instead.
static LPCWSTR getBcryptSHA1Algorithm()   { return BCRYPT_SHA1_ALGORITHM; }
static LPCWSTR getBcryptSHA256Algorithm() { return BCRYPT_SHA256_ALGORITHM; }
static LPCWSTR getBcryptSHA384Algorithm() { return BCRYPT_SHA384_ALGORITHM; }
static LPCWSTR getBcryptSHA512Algorithm() { return BCRYPT_SHA512_ALGORITHM; }

static HCERTSTORE certOpenStoreWithError(
    LPCSTR provider, DWORD encoding, HCRYPTPROV_LEGACY cryptProv,
    DWORD flags, const void *para, DWORD *lastError
) {
    HCERTSTORE store = CertOpenStore(provider, encoding, cryptProv, flags, para);
    *lastError = store == NULL ? GetLastError() : ERROR_SUCCESS;
    return store;
}

static BOOL cryptAcquireCertificatePrivateKeyWithError(
    PCCERT_CONTEXT cert, DWORD flags,
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *key, DWORD *keySpec,
    BOOL *callerFree, DWORD *lastError
) {
    BOOL ok = CryptAcquireCertificatePrivateKey(cert, flags, NULL, key, keySpec, callerFree);
    *lastError = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}

static PCCERT_CONTEXT certDuplicateCertificateContextWithError(
    PCCERT_CONTEXT cert, DWORD *lastError
) {
    PCCERT_CONTEXT duplicate = CertDuplicateCertificateContext(cert);
    *lastError = duplicate == NULL ? GetLastError() : ERROR_SUCCESS;
    return duplicate;
}

static BOOL cryptCreateHashWithError(
    HCRYPTPROV provider, ALG_ID algorithm, HCRYPTKEY key, DWORD flags,
    HCRYPTHASH *hash, DWORD *lastError
) {
    BOOL ok = CryptCreateHash(provider, algorithm, key, flags, hash);
    *lastError = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}

static BOOL cryptSetHashParamWithError(
    HCRYPTHASH hash, DWORD param, const BYTE *data, DWORD flags,
    DWORD *lastError
) {
    BOOL ok = CryptSetHashParam(hash, param, data, flags);
    *lastError = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}

static BOOL cryptSignHashWithError(
    HCRYPTHASH hash, DWORD keySpec, DWORD flags, BYTE *signature,
    DWORD *signatureLength, DWORD *lastError
) {
    BOOL ok = CryptSignHashW(hash, keySpec, NULL, flags, signature, signatureLength);
    *lastError = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
}
*/
import "C"

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// Stable Windows ABI values from winerror.h / wincrypt.h. Defined in Go so
// builds do not depend on toolchain-specific macro signedness when converting
// header constants through cgo. Prefer this pattern for any future NTE_*,
// CRYPT_E_*, SEC_E_*, or CERT_E_* mappings.
const (
	errNTESilentContext = syscall.Errno(0x80090022) // NTE_SILENT_CONTEXT
	certNCryptKeySpec   = uint32(0xFFFFFFFF)        // CERT_NCRYPT_KEY_SPEC
)

// openNativeStore opens a Windows system certificate store.
//
// Defaults match the historical behavior: CurrentUser\MY. Callers can select
// LocalMachine and/or another system store name through Options.
func openNativeStore(cfg Options) (Store, error) {
	location, storeName, err := resolveWindowsStoreConfig(cfg)
	if err != nil {
		return nil, err
	}

	var locationFlag C.DWORD
	switch location {
	case WindowsStoreCurrentUser:
		locationFlag = C.CERT_SYSTEM_STORE_CURRENT_USER
	case WindowsStoreLocalMachine:
		locationFlag = C.CERT_SYSTEM_STORE_LOCAL_MACHINE
	default:
		return nil, fmt.Errorf("%w: windows store location %q is unknown", ErrInvalidConfiguration, location)
	}

	nameUTF16, err := utf16PtrFromString(storeName)
	if err != nil {
		return nil, err
	}

	// Use SYSTEM_W explicitly: CERT_STORE_PROV_SYSTEM is a UNICODE-dependent
	// alias that may resolve to SYSTEM_A, which expects an ANSI pvPara.
	flags := locationFlag | C.CERT_STORE_READONLY_FLAG | C.CERT_STORE_OPEN_EXISTING_FLAG
	var lastErr C.DWORD
	h := C.certOpenStoreWithError(
		C.CERT_STORE_PROV_SYSTEM_W,
		0,
		0,
		flags,
		unsafe.Pointer(&nameUTF16[0]),
		&lastErr,
	)
	if h == nil {
		return nil, fmt.Errorf("open windows store %s\\%s: %w", location, storeName, windowsError("CertOpenStore", lastErr))
	}
	return &winStore{h: h}, nil
}

type winStore struct {
	mu sync.Mutex
	h  C.HCERTSTORE
}

func (s *winStore) Identities(ctx context.Context) ([]Identity, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.h == nil {
		return nil, ErrClosed
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.h != nil {
		C.CertCloseStore(s.h, 0)
		s.h = nil
	}
}

type winIdentity struct {
	ctx        *C.CERT_CONTEXT
	chainCerts []*x509.Certificate // parsed eagerly; see Identities()
	mu         sync.Mutex
	cert       *x509.Certificate
	closeOnce  sync.Once
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
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.certificateLocked()
}

func (id *winIdentity) certificateLocked() (*x509.Certificate, error) {
	if id.cert != nil {
		return id.cert, nil
	}
	if id.ctx == nil {
		return nil, ErrClosed
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
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	id.mu.Lock()
	defer id.mu.Unlock()
	if id.ctx == nil {
		return nil, ErrClosed
	}
	if len(id.chainCerts) > 0 {
		return id.chainCerts, nil
	}
	cert, err := id.certificateLocked()
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

func (id *winIdentity) Signer(ctx context.Context) (crypto.Signer, error) {
	return id.signer(ctx, false)
}

func windowsPrivateKeyAcquireFlags(cachePrivateKey bool) C.DWORD {
	flags := C.DWORD(C.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | C.CRYPT_ACQUIRE_SILENT_FLAG)
	if cachePrivateKey {
		flags |= C.CRYPT_ACQUIRE_CACHE_FLAG
	}
	return flags
}

func (id *winIdentity) signer(ctx context.Context, cachePrivateKey bool) (crypto.Signer, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	id.mu.Lock()
	defer id.mu.Unlock()
	if id.ctx == nil {
		return nil, ErrClosed
	}

	cert, err := id.certificateLocked()
	if err != nil {
		return nil, fmt.Errorf("load Windows certificate for signer: %w", err)
	}

	var (
		keyHandle  C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
		keySpec    C.DWORD
		callerFree C.BOOL
		lastErr    C.DWORD
	)

	// Prefer CNG (NCrypt) keys but fall back to CryptoAPI (legacy).
	ok := C.cryptAcquireCertificatePrivateKeyWithError(
		id.ctx,
		windowsPrivateKeyAcquireFlags(cachePrivateKey),
		&keyHandle,
		&keySpec,
		&callerFree,
		&lastErr,
	)
	if ok == 0 {
		return nil, fmt.Errorf("create Windows signer: %w", windowsError("CryptAcquireCertificatePrivateKey", lastErr))
	}

	isNCrypt := uint32(keySpec) == certNCryptKeySpec
	signer := &winSigner{
		pub:        cert.PublicKey,
		keyHandle:  keyHandle,
		keySpec:    keySpec,
		isNCrypt:   isNCrypt,
		callerFree: callerFree != 0,
	}
	if !signer.callerFree {
		signer.certCtx = C.certDuplicateCertificateContextWithError(id.ctx, &lastErr)
		if signer.certCtx == nil {
			signer.keyHandle = 0
			return nil, fmt.Errorf("create Windows signer: %w", windowsError("CertDuplicateCertificateContext", lastErr))
		}
	}
	runtime.SetFinalizer(signer, (*winSigner).release)
	return signer, nil
}

func (id *winIdentity) Close() {
	id.closeOnce.Do(func() {
		id.mu.Lock()
		defer id.mu.Unlock()
		if id.ctx != nil {
			C.CertFreeCertificateContext(id.ctx)
			id.ctx = nil
		}
	})
}

type winSigner struct {
	mu         sync.Mutex
	pub        crypto.PublicKey
	keyHandle  C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
	keySpec    C.DWORD
	certCtx    *C.CERT_CONTEXT
	isNCrypt   bool
	callerFree bool
}

func (s *winSigner) release() {
	if s.keyHandle != 0 && s.callerFree {
		if s.isNCrypt {
			C.NCryptFreeObject(C.NCRYPT_HANDLE(s.keyHandle))
		} else {
			C.CryptReleaseContext(C.HCRYPTPROV(s.keyHandle), 0)
		}
	}
	s.keyHandle = 0
	if s.certCtx != nil {
		C.CertFreeCertificateContext(s.certCtx)
		s.certCtx = nil
	}
}

func (s *winSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
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
		return nil, securityStatusError("NCryptSignHash (size)", status)
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
		return nil, securityStatusError("NCryptSignHash (sign)", status)
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
		return nil, fmt.Errorf("%w: CryptoAPI private keys do not support RSA-PSS signing", ErrMechanismUnsupported)
	}
	if _, ok := s.pub.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("%w: CryptoAPI private keys do not support %T", ErrMechanismUnsupported, s.pub)
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
	var lastErr C.DWORD
	if ok := C.cryptCreateHashWithError(C.HCRYPTPROV(s.keyHandle), algID, 0, 0, &cryptHash, &lastErr); ok == 0 {
		return nil, windowsError("CryptCreateHash", lastErr)
	}
	defer C.CryptDestroyHash(cryptHash)

	if ok := C.cryptSetHashParamWithError(cryptHash, C.HP_HASHVAL, (*C.BYTE)(byteSlicePtr(digest)), 0, &lastErr); ok == 0 {
		return nil, windowsError("CryptSetHashParam", lastErr)
	}

	// Get signature size.
	var sigLen C.DWORD
	if ok := C.cryptSignHashWithError(cryptHash, s.keySpec, 0, nil, &sigLen, &lastErr); ok == 0 {
		return nil, windowsError("CryptSignHash (size)", lastErr)
	}

	sig := make([]byte, sigLen)
	if ok := C.cryptSignHashWithError(cryptHash, s.keySpec, 0, (*C.BYTE)(byteSlicePtr(sig)), &sigLen, &lastErr); ok == 0 {
		return nil, windowsError("CryptSignHash", lastErr)
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

// windowsError wraps an error code captured in the same C call as the failing
// Windows API operation. Codes are represented as syscall.Errno so callers can
// unwrap them and so message formatting uses the standard library.
func windowsError(context string, code C.DWORD) error {
	return classifyWindowsStatus(context, uint32(code))
}

func securityStatusError(context string, status C.SECURITY_STATUS) error {
	return classifyWindowsStatus(context, uint32(status))
}

func classifyWindowsStatus(context string, code uint32) error {
	errno := syscall.Errno(code)
	if errno == errNTESilentContext {
		return fmt.Errorf("%s: %w: %w", context, ErrLoginRequired, errno)
	}
	return fmt.Errorf("%s: %w", context, errno)
}
