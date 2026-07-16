package certstore

import (
	"context"
	"crypto"
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

func TestClientCertificateFuncSelectsFromOpenStore(t *testing.T) {
	_, _, leafCert, leafKey := newTestChain(t, "Client Cert Func CA", true)
	store := &countingIdentitiesStore{
		idents: []Identity{
			&testIdentity{cert: leafCert, signer: leafKey},
		},
	}

	getClientCertificate := ClientCertificateFunc(context.Background(), store, SelectOptions{
		SubjectCN: leafCert.Subject.CommonName,
	})
	req := &tls.CertificateRequestInfo{
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
	}

	got, err := getClientCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf == nil || got.Leaf.Subject.CommonName != leafCert.Subject.CommonName {
		t.Fatalf("unexpected certificate: %#v", got.Leaf)
	}
	if store.identitiesCalls != 1 {
		t.Fatalf("Identities called %d times, want 1", store.identitiesCalls)
	}

	gotAgain, err := getClientCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	if gotAgain != got {
		t.Fatal("expected cached tls.Certificate to be reused")
	}
	if store.identitiesCalls != 1 {
		t.Fatalf("Identities called %d times after reuse, want 1", store.identitiesCalls)
	}
	if store.closeCalls != 0 {
		t.Fatalf("store closed %d times, want 0", store.closeCalls)
	}
}

func TestClientCertificateSourceClosesCachedSigner(t *testing.T) {
	_, _, leafCert, leafKey := newTestChain(t, "Client Cert Source CA", true)
	closeCalls := 0
	store := &countingIdentitiesStore{
		idents: []Identity{
			&testIdentity{
				cert:   leafCert,
				signer: &testCloseableSigner{Signer: leafKey, closeCalls: &closeCalls},
			},
		},
	}

	source := NewClientCertificateSource(context.Background(), store, SelectOptions{
		SubjectCN: leafCert.Subject.CommonName,
	})
	req := &tls.CertificateRequestInfo{
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
	}

	if _, err := source.GetClientCertificate(req); err != nil {
		t.Fatal(err)
	}
	if closeCalls != 0 {
		t.Fatalf("signer closed %d times before source.Close", closeCalls)
	}

	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if closeCalls != 1 {
		t.Fatalf("signer closed %d times, want 1", closeCalls)
	}

	if _, err := source.GetClientCertificate(req); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed after Close, got %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if closeCalls != 1 {
		t.Fatalf("signer closed %d times after repeated Close, want 1", closeCalls)
	}
}

func TestClientCertificateSourceKeepsReturnedCertificatesUntilClose(t *testing.T) {
	caA, _, leafA, keyA := newTestChain(t, "Cache Keep CA A", true)
	caB, _, leafB, keyB := newTestChain(t, "Cache Keep CA B", true)
	closeA := 0
	closeB := 0
	store := &countingIdentitiesStore{
		idents: []Identity{
			&renewingCloseableIdentity{
				testIdentity: &testIdentity{
					cert:   leafA,
					chain:  []*x509.Certificate{leafA, caA},
					signer: keyA,
				},
				closeCalls: &closeA,
			},
			&renewingCloseableIdentity{
				testIdentity: &testIdentity{
					cert:   leafB,
					chain:  []*x509.Certificate{leafB, caB},
					signer: keyB,
				},
				closeCalls: &closeB,
			},
		},
	}

	source := NewClientCertificateSource(context.Background(), store, SelectOptions{})

	reqA := &tls.CertificateRequestInfo{
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		AcceptableCAs:    [][]byte{caA.RawSubject},
	}
	reqB := &tls.CertificateRequestInfo{
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		AcceptableCAs:    [][]byte{caB.RawSubject},
	}

	first, err := source.GetClientCertificate(reqA)
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(leafA.SerialNumber) != 0 {
		t.Fatal("expected first selection to use CA A")
	}
	// Selecting for CA A discards a fresh CA B candidate signer.
	if closeA != 0 {
		t.Fatalf("returned CA A signer closed %d times, want 0", closeA)
	}
	if closeB != 1 {
		t.Fatalf("discarded CA B signer closed %d times, want 1", closeB)
	}

	second, err := source.GetClientCertificate(reqB)
	if err != nil {
		t.Fatal(err)
	}
	if second.Leaf.SerialNumber.Cmp(leafB.SerialNumber) != 0 {
		t.Fatal("expected second selection to use CA B")
	}
	// Selecting for CA B discards a fresh CA A candidate, but must not close the
	// previously returned CA A certificate still in use by another handshake.
	if closeA != 1 {
		t.Fatalf("CA A signer closed %d times after incompatible selection, want 1", closeA)
	}
	if closeB != 1 {
		t.Fatalf("returned CA B signer closed %d times before source.Close, want 1", closeB)
	}

	againA, err := source.GetClientCertificate(reqA)
	if err != nil {
		t.Fatal(err)
	}
	if againA != first {
		t.Fatal("expected original CA A certificate to remain cached")
	}
	if store.identitiesCalls != 2 {
		t.Fatalf("Identities called %d times, want 2", store.identitiesCalls)
	}

	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	// One discarded candidate during the other request, plus each cached return.
	if closeA != 2 {
		t.Fatalf("CA A signer closed %d times after Close, want 2", closeA)
	}
	if closeB != 2 {
		t.Fatalf("CA B signer closed %d times after Close, want 2", closeB)
	}
}

func TestClientCertificateSourceSkipsExpiredCachedCertificate(t *testing.T) {
	_, _, expiredLeaf, expiredKey := newTestChainWithExpiry(
		t,
		"Expired Cache CA",
		true,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-time.Hour),
	)
	_, _, validLeaf, validKey := newTestChain(t, "Valid Cache CA", true)

	expiredCloseCalls := 0
	store := &countingIdentitiesStore{
		idents: []Identity{
			&testIdentity{cert: validLeaf, signer: validKey},
		},
	}
	source := NewClientCertificateSource(context.Background(), store, SelectOptions{})
	source.cached = []*tls.Certificate{{
		Certificate: [][]byte{expiredLeaf.Raw},
		PrivateKey:  &testCloseableSigner{Signer: expiredKey, closeCalls: &expiredCloseCalls},
		Leaf:        expiredLeaf,
	}}

	req := &tls.CertificateRequestInfo{
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
	}
	got, err := source.GetClientCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf.SerialNumber.Cmp(validLeaf.SerialNumber) != 0 {
		t.Fatal("expected expired cache entry to be skipped")
	}
	if expiredCloseCalls != 0 {
		t.Fatalf("expired cached signer closed %d times before Close, want 0", expiredCloseCalls)
	}
	if store.identitiesCalls != 1 {
		t.Fatalf("Identities called %d times, want 1", store.identitiesCalls)
	}

	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if expiredCloseCalls != 1 {
		t.Fatalf("expired cached signer closed %d times after Close, want 1", expiredCloseCalls)
	}
}

func TestClientCertificateSourceRejectsExpiredOnlyStore(t *testing.T) {
	_, _, expiredLeaf, expiredKey := newTestChainWithExpiry(
		t,
		"Expired Only CA",
		true,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-time.Hour),
	)
	signerCalls := 0
	store := &countingIdentitiesStore{
		idents: []Identity{
			&countingSignerIdentity{
				testIdentity: &testIdentity{cert: expiredLeaf, signer: expiredKey},
				signerCalls:  &signerCalls,
			},
		},
	}
	source := NewClientCertificateSource(context.Background(), store, SelectOptions{})
	defer source.Close()

	req := &tls.CertificateRequestInfo{
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
	}
	if _, err := source.GetClientCertificate(req); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound, got %v", err)
	}
	if _, err := source.GetClientCertificate(req); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound on retry, got %v", err)
	}
	if signerCalls != 0 {
		t.Fatalf("Signer called %d times for expired-only store, want 0", signerCalls)
	}
	if len(source.cached) != 0 {
		t.Fatalf("cached %d certificates, want 0", len(source.cached))
	}
}

func TestCachedCertificateReusableRejectsExpiredLeaf(t *testing.T) {
	_, _, expiredLeaf, expiredKey := newTestChainWithExpiry(
		t,
		"Reusable Expired CA",
		true,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-time.Hour),
	)
	cert := &tls.Certificate{
		Certificate: [][]byte{expiredLeaf.Raw},
		PrivateKey:  expiredKey,
		Leaf:        expiredLeaf,
	}
	if cachedCertificateReusable(cert, nil, time.Now()) {
		t.Fatal("expected expired certificate not to be reusable")
	}
}

type renewingCloseableIdentity struct {
	*testIdentity
	closeCalls *int
}

func (i *renewingCloseableIdentity) Signer(ctx context.Context) (crypto.Signer, error) {
	signer, err := i.testIdentity.Signer(ctx)
	if err != nil {
		return nil, err
	}
	return &testCloseableSigner{Signer: signer, closeCalls: i.closeCalls}, nil
}

type countingSignerIdentity struct {
	*testIdentity
	signerCalls *int
}

func (i *countingSignerIdentity) Signer(ctx context.Context) (crypto.Signer, error) {
	if i.signerCalls != nil {
		(*i.signerCalls)++
	}
	return i.testIdentity.Signer(ctx)
}

type countingIdentitiesStore struct {
	idents          []Identity
	identitiesCalls int
	closeCalls      int
}

func (s *countingIdentitiesStore) Identities(context.Context) ([]Identity, error) {
	s.identitiesCalls++
	// Return a copy so findTLSCertificate's in-place niling does not clear the store.
	out := make([]Identity, len(s.idents))
	copy(out, s.idents)
	return out, nil
}

func (s *countingIdentitiesStore) Close() {
	s.closeCalls++
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
