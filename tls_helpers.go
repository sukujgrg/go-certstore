package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"time"
)

// SelectOptions controls how a client certificate is selected for TLS use.
type SelectOptions struct {
	SubjectCN            string
	IssuerCN             string
	RequireClientAuthEKU bool
	PreferHardwareBacked bool
}

// FindTLSCertificate selects the best matching identity from an open store and
// converts it into a tls.Certificate.
func FindTLSCertificate(store Store, opts SelectOptions) (*tls.Certificate, error) {
	return findTLSCertificate(store, opts, nil)
}

// GetClientCertificateFunc returns a callback suitable for
// tls.Config.GetClientCertificate. It opens the store on each invocation and
// selects the best matching identity for the server's request.
func GetClientCertificateFunc(openOpts []Option, selectOpts SelectOptions) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		store, err := Open(openOpts...)
		if err != nil {
			return nil, err
		}
		defer store.Close()
		return findTLSCertificate(store, selectOpts, info)
	}
}

type supportedSignatureAlgorithmProvider interface {
	supportedSignatureAlgorithms() []tls.SignatureScheme
}

func findTLSCertificate(store Store, opts SelectOptions, req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	idents, err := store.Identities()
	if err != nil {
		return nil, err
	}

	var (
		best      *tls.Certificate
		bestScore int
		found     bool
	)

	for _, ident := range idents {
		candidate, score, ok := tlsCertificateCandidate(ident, opts, req)
		ident.Close()
		if !ok {
			continue
		}
		if !found || score > bestScore {
			best = candidate
			bestScore = score
			found = true
		}
	}

	if !found {
		return nil, ErrIdentityNotFound
	}
	return best, nil
}

func tlsCertificateCandidate(ident Identity, opts SelectOptions, req *tls.CertificateRequestInfo) (*tls.Certificate, int, bool) {
	cert, err := ident.Certificate()
	if err != nil || !matchesTLSCertificate(cert, opts) {
		return nil, 0, false
	}

	signer, err := ident.Signer()
	if err != nil {
		return nil, 0, false
	}

	chain, err := ident.CertificateChain()
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
			return nil, 0, false
		}
	}

	return tlsCert, scoreTLSIdentity(ident, cert, opts), true
}

func matchesTLSCertificate(cert *x509.Certificate, opts SelectOptions) bool {
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
			score += 1000
		}
	}
	now := time.Now()
	if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
		score += 100
	}
	score += int(cert.NotAfter.Sub(now).Hours() / 24)
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
		return []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.ECDSAWithSHA1,
		}
	case ed25519.PublicKey:
		return []tls.SignatureScheme{tls.Ed25519}
	default:
		return nil
	}
}
