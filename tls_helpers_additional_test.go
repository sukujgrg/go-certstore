package certstore

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
)

func TestGetClientCertificateFuncOpenError(t *testing.T) {
	getClientCertificate := GetClientCertificateFunc(context.Background(), []Option{
		WithBackend(BackendPKCS11),
	}, SelectOptions{})

	_, err := getClientCertificate(&tls.CertificateRequestInfo{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "pkcs11 module path is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSupportedSignatureAlgorithmsForPublicKey(t *testing.T) {
	_, _, cert, key := newTestChain(t, "Signature CA", true)

	if got := supportedSignatureAlgorithmsForPublicKey(key.Public()); len(got) == 0 {
		t.Fatal("expected ECDSA signature schemes")
	}

	rsaCertCA, _, _, _ := newTestChain(t, "RSA CA", true)
	if got := supportedSignatureAlgorithmsForPublicKey(rsaCertCA.PublicKey); len(got) == 0 {
		t.Fatal("expected RSA signature schemes")
	}

	if got := supportedSignatureAlgorithmsForPublicKey(struct{}{}); got != nil {
		t.Fatalf("unexpected signature schemes for unsupported key: %v", got)
	}

	if got := supportedSignatureAlgorithmsForPublicKey(cert.PublicKey); len(got) == 0 {
		t.Fatal("expected signature schemes for leaf public key")
	}
}

func TestFindTLSCertificateIdentityNotFound(t *testing.T) {
	store := &testStore{}
	_, err := FindTLSCertificate(context.Background(), store, SelectOptions{})
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound, got %v", err)
	}
}
