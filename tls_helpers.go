package certstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// SelectOptions controls how a client certificate is selected for TLS use.
//
// When multiple identities match these filters, FindTLSCertificate returns a
// single best candidate rather than all matches. The current scoring ranks
// identities known to be hardware-backed above other matches when
// PreferHardwareBacked is set, gives a smaller bonus to currently valid
// certificates, and also favors later expiry. This is a scoring heuristic, not
// a strict lexicographic ordering.
type SelectOptions struct {
	SubjectCN string
	IssuerCN  string
	// RequireClientAuthEKU rejects certificates whose ExtKeyUsage list is
	// present and does not include ClientAuth or Any. Certificates with no
	// ExtKeyUsage extensions are treated as unrestricted per X.509 semantics
	// and are accepted.
	RequireClientAuthEKU bool
	// RequireCurrentlyValid rejects certificates outside NotBefore/NotAfter.
	// ClientCertificateSource always enables this so expired identities are not
	// re-selected and cached after an expired cache entry is skipped.
	RequireCurrentlyValid bool
	PreferHardwareBacked bool
}

// FindTLSCertificate selects the best matching identity from an open store and
// converts it into a tls.Certificate.
//
// If more than one identity matches, it returns the highest-ranked candidate
// according to SelectOptions and internal scoring. Use FindIdentities or direct
// store enumeration if you need to inspect multiple matches instead of a single
// winner. ctx must not be nil.
func FindTLSCertificate(ctx context.Context, store Store, opts SelectOptions) (*tls.Certificate, error) {
	return findTLSCertificate(ctx, store, opts, nil)
}

// ClientCertificateSource selects client certificates from an open store and
// caches them for reuse across TLS handshakes.
//
// crypto/tls does not close tls.Certificate.PrivateKey, so returning a fresh
// PKCS#11/NSS signer on every handshake can exhaust token sessions until GC.
// This type retains previously returned certificates and reuses one when it
// still satisfies the server's CertificateRequestInfo and is currently valid.
// Expired or not-yet-valid cached certificates are skipped (not closed) so a
// newer valid identity can be selected; selection itself requires a currently
// valid leaf so an expired store identity is not re-opened and appended on
// every handshake. Previously returned signers stay alive until Close for
// in-flight handshakes.
//
// Cache reuse does not detect store rotation (a replaced identity in Keychain,
// CertStore, or a token). Callers that need to pick up replacements should
// recreate the source, or keep process lifetime aligned with certificate
// lifetime.
//
// Call Close when the TLS client or server is done so cached signer sessions
// are released deterministically. Prefer this over ClientCertificateFunc when
// you need explicit cleanup.
type ClientCertificateSource struct {
	ctx   context.Context
	store Store
	opts  SelectOptions

	mu     sync.Mutex
	cached []*tls.Certificate
	closed bool
}

// NewClientCertificateSource returns a TLS client-certificate source for store.
// The caller must Close the source when finished. ctx must not be nil.
func NewClientCertificateSource(ctx context.Context, store Store, opts SelectOptions) *ClientCertificateSource {
	return &ClientCertificateSource{
		ctx:   ctx,
		store: store,
		opts:  opts,
	}
}

// GetClientCertificate is suitable for tls.Config.GetClientCertificate.
//
// It reuses a previously selected certificate when that certificate is still
// within its validity window and satisfies info, avoiding a new token session
// per handshake. Otherwise it selects another certificate and keeps prior
// returns alive until Close.
func (s *ClientCertificateSource) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrClosed
	}
	if err := contextReady(s.ctx); err != nil {
		return nil, err
	}
	if s.store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfiguration)
	}

	now := time.Now()
	for _, cert := range s.cached {
		if cachedCertificateReusable(cert, info, now) {
			return cert, nil
		}
	}

	// Require a currently valid leaf so skipping an expired cache entry cannot
	// re-select the same expired store identity and append another signer.
	opts := s.opts
	opts.RequireCurrentlyValid = true
	cert, err := findTLSCertificate(s.ctx, s.store, opts, info)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil || !isCertificateCurrentlyValid(cert.Leaf, now) {
		closeTLSCertificate(cert)
		return nil, ErrIdentityNotFound
	}
	s.cached = append(s.cached, cert)
	return cert, nil
}

// Close releases all cached signer resources. It is safe to call more than once.
func (s *ClientCertificateSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, cert := range s.cached {
		closeTLSCertificate(cert)
	}
	s.cached = nil
	return nil
}

// ClientCertificateFunc returns a callback suitable for
// tls.Config.GetClientCertificate that selects from an already-open store and
// caches returned certificates across handshakes.
//
// Prefer this over GetClientCertificateFunc for PKCS#11 and NSS: the caller
// owns store lifetime and avoids reopening the backend on every handshake.
// The callback reuses a compatible cached certificate/signer so token sessions
// are not created per handshake, and keeps previously returned certificates
// alive until the underlying source is closed.
//
// For deterministic signer cleanup, prefer NewClientCertificateSource and call
// Close when the TLS client or server shuts down. This convenience wrapper keeps
// the cache alive with the returned function but does not expose Close.
//
// The callback reuses the supplied context on each invocation; because the Go
// TLS hook does not expose a per-handshake context, callers should typically
// pass a long-lived context. ctx must not be nil.
func ClientCertificateFunc(ctx context.Context, store Store, selectOpts SelectOptions) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return NewClientCertificateSource(ctx, store, selectOpts).GetClientCertificate
}

// GetClientCertificateFunc returns a callback suitable for
// tls.Config.GetClientCertificate. It opens the store on each invocation and
// selects the best matching identity for the server's request.
//
// This is convenient for short-lived native-store use, but reopen cost is
// painful for PKCS#11 and NSS. Prefer NewClientCertificateSource or
// ClientCertificateFunc with a long-lived store for token backends.
//
// Like FindTLSCertificate, this returns at most one certificate even when
// multiple identities match. The callback reuses the supplied context on each
// invocation; because the Go TLS hook does not expose a per-handshake context,
// callers should typically pass a long-lived context. ctx must not be nil.
func GetClientCertificateFunc(ctx context.Context, openOpts []Option, selectOpts SelectOptions) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if err := contextReady(ctx); err != nil {
			return nil, err
		}
		store, err := Open(ctx, openOpts...)
		if err != nil {
			return nil, err
		}
		defer store.Close()
		return findTLSCertificate(ctx, store, selectOpts, info)
	}
}

func cachedCertificateReusable(cert *tls.Certificate, info *tls.CertificateRequestInfo, now time.Time) bool {
	if cert == nil || cert.Leaf == nil {
		return false
	}
	if !isCertificateCurrentlyValid(cert.Leaf, now) {
		return false
	}
	return certificateSatisfiesRequest(cert, info)
}

func certificateSatisfiesRequest(cert *tls.Certificate, info *tls.CertificateRequestInfo) bool {
	if cert == nil {
		return false
	}
	if info == nil {
		return true
	}
	return info.SupportsCertificate(cert) == nil
}

type supportedSignatureAlgorithmProvider interface {
	supportedSignatureAlgorithms() []tls.SignatureScheme
}

func findTLSCertificate(ctx context.Context, store Store, opts SelectOptions, req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfiguration)
	}

	idents, err := store.Identities(ctx)
	if err != nil {
		return nil, fmt.Errorf("list identities for TLS selection: %w", err)
	}

	var (
		best      *tls.Certificate
		bestScore int
		found     bool
	)

	for i, ident := range idents {
		if err := ctx.Err(); err != nil {
			closeOpenIdentities(idents)
			closeTLSCertificate(best)
			return nil, err
		}
		if ident == nil {
			continue
		}
		candidate, score, ok := tlsCertificateCandidate(ctx, ident, opts, req)
		ident.Close()
		idents[i] = nil
		if !ok {
			continue
		}
		if !found || score > bestScore {
			closeTLSCertificate(best)
			best = candidate
			bestScore = score
			found = true
			continue
		}
		closeTLSCertificate(candidate)
	}

	if !found {
		return nil, ErrIdentityNotFound
	}
	return best, nil
}

func tlsCertificateCandidate(ctx context.Context, ident Identity, opts SelectOptions, req *tls.CertificateRequestInfo) (*tls.Certificate, int, bool) {
	cert, err := ident.Certificate(ctx)
	if err != nil || !matchesTLSCertificate(cert, opts) {
		return nil, 0, false
	}

	signer, err := ident.Signer(ctx)
	if err != nil {
		return nil, 0, false
	}

	chain, err := ident.CertificateChain(ctx)
	if err != nil || len(chain) == 0 {
		chain = []*x509.Certificate{cert}
	}

	tlsCert := &tls.Certificate{
		PrivateKey: signer,
		Leaf:       cert,
	}
	tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
	for _, c := range chain {
		if c == nil || len(c.Raw) == 0 || bytes.Equal(c.Raw, cert.Raw) {
			continue
		}
		tlsCert.Certificate = append(tlsCert.Certificate, c.Raw)
	}

	if provider, ok := signer.(supportedSignatureAlgorithmProvider); ok {
		tlsCert.SupportedSignatureAlgorithms = provider.supportedSignatureAlgorithms()
	}

	if req != nil {
		if err := req.SupportsCertificate(tlsCert); err != nil {
			_ = CloseSigner(signer)
			return nil, 0, false
		}
	}

	return tlsCert, scoreTLSIdentity(ident, cert, opts), true
}

func closeTLSCertificate(cert *tls.Certificate) {
	if cert == nil {
		return
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return
	}
	_ = CloseSigner(signer)
}

func matchesTLSCertificate(cert *x509.Certificate, opts SelectOptions) bool {
	if cert == nil {
		return false
	}
	if opts.SubjectCN != "" && cert.Subject.CommonName != opts.SubjectCN {
		return false
	}
	if opts.IssuerCN != "" && cert.Issuer.CommonName != opts.IssuerCN {
		return false
	}
	if opts.RequireClientAuthEKU && !hasClientAuthEKU(cert) {
		return false
	}
	if opts.RequireCurrentlyValid && !isCertificateCurrentlyValid(cert, time.Now()) {
		return false
	}
	return true
}

// hasClientAuthEKU returns true when the certificate is usable for client
// authentication. Per X.509 semantics, certificates with no ExtKeyUsage
// extensions are unrestricted and always pass.
func hasClientAuthEKU(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny || eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func scoreTLSIdentity(ident Identity, cert *x509.Certificate, opts SelectOptions) int {
	score := 0
	if opts.PreferHardwareBacked {
		if identityHardwareBackedState(ident) == CapabilityYes {
			score += identityScoreHardwareBackedPreferred
		}
	}
	now := time.Now()
	if isCertificateCurrentlyValid(cert, now) {
		score += identityScoreCurrentlyValid
	}
	score += int(cert.NotAfter.Sub(now).Hours()/24) * identityScorePerDayUntilExpiry
	return score
}

func supportedSignatureAlgorithmsForPublicKey(pub crypto.PublicKey) []tls.SignatureScheme {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return []tls.SignatureScheme{
			tls.PSSWithSHA256,
			tls.PSSWithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA256,
			tls.PKCS1WithSHA384,
			tls.PKCS1WithSHA512,
			tls.PKCS1WithSHA1,
		}
	case *ecdsa.PublicKey:
		if pub.Curve == nil {
			return nil
		}
		switch pub.Curve {
		case elliptic.P256():
			return []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.ECDSAWithSHA1}
		case elliptic.P384():
			return []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384, tls.ECDSAWithSHA1}
		case elliptic.P521():
			return []tls.SignatureScheme{tls.ECDSAWithP521AndSHA512, tls.ECDSAWithSHA1}
		default:
			return nil
		}
	case ed25519.PublicKey:
		return []tls.SignatureScheme{tls.Ed25519}
	default:
		return nil
	}
}
