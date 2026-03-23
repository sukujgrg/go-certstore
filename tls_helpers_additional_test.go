package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
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

func TestSupportedSignatureAlgorithmsForECDSACurve(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportedSignatureAlgorithmsForPublicKey(&p256Key.PublicKey); len(got) != 2 || got[0] != tls.ECDSAWithP256AndSHA256 || got[1] != tls.ECDSAWithSHA1 {
		t.Fatalf("unexpected P-256 schemes: %v", got)
	}

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportedSignatureAlgorithmsForPublicKey(&p384Key.PublicKey); len(got) != 2 || got[0] != tls.ECDSAWithP384AndSHA384 || got[1] != tls.ECDSAWithSHA1 {
		t.Fatalf("unexpected P-384 schemes: %v", got)
	}

	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := supportedSignatureAlgorithmsForPublicKey(&p521Key.PublicKey); len(got) != 2 || got[0] != tls.ECDSAWithP521AndSHA512 || got[1] != tls.ECDSAWithSHA1 {
		t.Fatalf("unexpected P-521 schemes: %v", got)
	}
}

func TestFindTLSCertificateClosesIdentitiesOnCancellation(t *testing.T) {
	_, _, certA, keyA := newTestChain(t, "TLS Cancel CA A", true)
	_, _, certB, keyB := newTestChain(t, "TLS Cancel CA B", true)

	ctx, cancel := context.WithCancel(context.Background())
	var signerCloses int

	idA := &cancelingTLSIdentity{
		testIdentity: testIdentity{
			cert:   certA,
			signer: &testCloseableSigner{Signer: keyA, closeCalls: &signerCloses},
		},
		onCertificate: func(call int) {
			if call == 1 {
				cancel()
			}
		},
	}
	idB := &cancelingTLSIdentity{
		testIdentity: testIdentity{
			cert:   certB,
			signer: keyB,
		},
	}

	store := &testStore{idents: []Identity{idA, idB}}
	_, err := FindTLSCertificate(ctx, store, SelectOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if idA.closeCalls != 1 {
		t.Fatalf("first identity closed %d times", idA.closeCalls)
	}
	if idB.closeCalls != 1 {
		t.Fatalf("second identity closed %d times", idB.closeCalls)
	}
	if signerCloses != 1 {
		t.Fatalf("winning signer closed %d times", signerCloses)
	}
}

func TestFindTLSCertificateHardwarePreferenceDominatesLongExpiry(t *testing.T) {
	now := time.Now()
	_, _, softCert, softKey := newTestChainWithExpiry(t, "TLS Long CA", true, now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	_, _, hwCert, hwKey := newTestChainWithExpiry(t, "TLS Short CA", true, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:   softCert,
				signer: softKey,
				info:   testIdentityInfo{backend: BackendPKCS11, hardware: false},
			},
			&testIdentity{
				cert:   hwCert,
				signer: hwKey,
				info:   testIdentityInfo{backend: BackendPKCS11, hardware: true},
			},
		},
	}

	got, err := FindTLSCertificate(context.Background(), store, SelectOptions{PreferHardwareBacked: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf.SerialNumber.Cmp(hwCert.SerialNumber) != 0 {
		t.Fatal("expected hardware-backed identity to win despite shorter expiry")
	}
}

func TestFindTLSCertificateSkipsIdentityWithSignerError(t *testing.T) {
	_, _, certA, _ := newTestChain(t, "Signer Fail CA A", true)
	_, _, certB, keyB := newTestChain(t, "Signer Fail CA B", true)

	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:      certA,
				signerErr: errors.New("token unavailable"),
			},
			&testIdentity{
				cert:   certB,
				signer: keyB,
			},
		},
	}

	got, err := FindTLSCertificate(context.Background(), store, SelectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf.SerialNumber.Cmp(certB.SerialNumber) != 0 {
		t.Fatal("expected identity with working signer to be selected")
	}
}

func TestFindTLSCertificateIdentityNotFound(t *testing.T) {
	store := &testStore{}
	_, err := FindTLSCertificate(context.Background(), store, SelectOptions{})
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound, got %v", err)
	}
}

type cancelingTLSIdentity struct {
	testIdentity
	closeCalls    int
	certCalls     int
	onCertificate func(int)
}

func (i *cancelingTLSIdentity) Certificate(context.Context) (*x509.Certificate, error) {
	i.certCalls++
	if i.onCertificate != nil {
		i.onCertificate(i.certCalls)
	}
	return i.cert, nil
}

func (i *cancelingTLSIdentity) Close() {
	i.closeCalls++
}
