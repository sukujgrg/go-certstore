package certstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	SubjectCN            string
	IssuerCN             string
	RequireClientAuthEKU bool
	PreferHardwareBacked bool
}

// FindTLSCertificate selects the best matching identity from an open store and
// converts it into a tls.Certificate.
//
// If more than one identity matches, it returns the highest-ranked candidate
// according to SelectOptions and internal scoring. Use FindIdentities or direct
// store enumeration if you need to inspect multiple matches instead of a single
// winner. Passing nil is treated as context.Background().
func FindTLSCertificate(ctx context.Context, store Store, opts SelectOptions) (*tls.Certificate, error) {
	return findTLSCertificate(ctx, store, opts, nil)
}

// GetClientCertificateFunc returns a callback suitable for
// tls.Config.GetClientCertificate. It opens the store on each invocation and
// selects the best matching identity for the server's request.
//
// Like FindTLSCertificate, this returns at most one certificate even when
// multiple identities match. The callback reuses the supplied context on each
// invocation; because the Go TLS hook does not expose a per-handshake context,
// callers should typically pass a long-lived context. Passing nil is treated as
// context.Background().
func GetClientCertificateFunc(ctx context.Context, openOpts []Option, selectOpts SelectOptions) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		callCtx := normalizeContext(ctx)
		if err := callCtx.Err(); err != nil {
			return nil, err
		}
		store, err := Open(callCtx, openOpts...)
		if err != nil {
			return nil, err
		}
		defer store.Close()
		return findTLSCertificate(callCtx, store, selectOpts, info)
	}
}

type supportedSignatureAlgorithmProvider interface {
	supportedSignatureAlgorithms() []tls.SignatureScheme
}

func findTLSCertificate(ctx context.Context, store Store, opts SelectOptions, req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
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
		Certificate: make([][]byte, 0, len(chain)),
		PrivateKey:  signer,
		Leaf:        cert,
	}
	for _, c := range chain {
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
	return true
}

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
	if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
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
