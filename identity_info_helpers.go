package certstore

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

func identityLabelFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

func identityKeyTypeFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	default:
		if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			return ""
		}
		return cert.PublicKeyAlgorithm.String()
	}
}

func identityURIFromCert(backend Backend, cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return string(backend) + ":sha256=" + hex.EncodeToString(sum[:])
}
