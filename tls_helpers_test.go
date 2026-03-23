package certstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type testCloseableSigner struct {
	crypto.Signer
	closeCalls *int
}

func (s *testCloseableSigner) Close() error {
	if s.closeCalls != nil {
		(*s.closeCalls)++
	}
	return nil
}

type testStore struct {
	idents []Identity
}

func (s *testStore) Identities(context.Context) ([]Identity, error) { return s.idents, nil }
func (s *testStore) Close()                                         {}

type testIdentity struct {
	cert      *x509.Certificate
	chain     []*x509.Certificate
	signer    crypto.Signer
	info      testIdentityInfo
	signerErr error
}

func (i *testIdentity) Certificate(context.Context) (*x509.Certificate, error) { return i.cert, nil }
func (i *testIdentity) CertificateChain(context.Context) ([]*x509.Certificate, error) {
	if len(i.chain) == 0 {
		return []*x509.Certificate{i.cert}, nil
	}
	return i.chain, nil
}
func (i *testIdentity) Signer(context.Context) (crypto.Signer, error) {
	if i.signerErr != nil {
		return nil, i.signerErr
	}
	return i.signer, nil
}
func (i *testIdentity) Close()                 {}
func (i *testIdentity) Label() string          { return i.info.label }
func (i *testIdentity) Backend() Backend       { return i.info.backend }
func (i *testIdentity) KeyType() string        { return i.info.keyType }
func (i *testIdentity) IsHardwareBacked() bool { return i.info.hardware }
func (i *testIdentity) RequiresLogin() bool    { return false }
func (i *testIdentity) URI() string            { return i.info.uri }
func (i *testIdentity) HardwareBackedState() CapabilityState {
	if i.info.hardwareStateSet {
		return i.info.hardwareState
	}
	if i.info.hardware {
		return CapabilityYes
	}
	return CapabilityNo
}
func (i *testIdentity) LoginRequiredState() CapabilityState {
	if i.info.loginStateSet {
		return i.info.loginState
	}
	return CapabilityNo
}

type testIdentityInfo struct {
	label            string
	backend          Backend
	keyType          string
	hardware         bool
	hardwareState    CapabilityState
	hardwareStateSet bool
	loginState       CapabilityState
	loginStateSet    bool
	uri              string
}

func TestFindTLSCertificateBuildsChain(t *testing.T) {
	caCert, _, leafCert, leafKey := newTestChain(t, "Test CA A", true)
	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:   leafCert,
				chain:  []*x509.Certificate{leafCert, caCert},
				signer: leafKey,
			},
		},
	}

	got, err := FindTLSCertificate(context.Background(), store, SelectOptions{
		SubjectCN:            leafCert.Subject.CommonName,
		IssuerCN:             caCert.Subject.CommonName,
		RequireClientAuthEKU: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf == nil || got.Leaf.Subject.CommonName != leafCert.Subject.CommonName {
		t.Fatal("expected helper to populate Leaf")
	}
	if len(got.Certificate) != 2 {
		t.Fatalf("expected full chain, got %d certs", len(got.Certificate))
	}
}

func TestFindTLSCertificatePrefersHardwareBacked(t *testing.T) {
	_, _, certA, keyA := newTestChain(t, "Test CA A", true)
	_, _, certB, keyB := newTestChain(t, "Test CA B", true)

	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:   certA,
				signer: keyA,
				info:   testIdentityInfo{backend: BackendPKCS11, hardware: false},
			},
			&testIdentity{
				cert:   certB,
				signer: keyB,
				info:   testIdentityInfo{backend: BackendPKCS11, hardware: true},
			},
		},
	}

	got, err := FindTLSCertificate(context.Background(), store, SelectOptions{PreferHardwareBacked: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf.SerialNumber.Cmp(certB.SerialNumber) != 0 {
		t.Fatal("expected hardware-backed identity to be preferred")
	}
}

func TestFindTLSCertificateRespectsCertificateRequest(t *testing.T) {
	caA, _, leafA, keyA := newTestChain(t, "Test CA A", true)
	caB, _, leafB, keyB := newTestChain(t, "Test CA B", true)
	store := &testStore{
		idents: []Identity{
			&testIdentity{cert: leafA, chain: []*x509.Certificate{leafA, caA}, signer: keyA},
			&testIdentity{cert: leafB, chain: []*x509.Certificate{leafB, caB}, signer: keyB},
		},
	}

	got, err := findTLSCertificate(context.Background(), store, SelectOptions{}, &tls.CertificateRequestInfo{
		Version:          tls.VersionTLS13,
		SignatureSchemes: []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256},
		AcceptableCAs:    [][]byte{caB.RawSubject},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf.SerialNumber.Cmp(leafB.SerialNumber) != 0 {
		t.Fatal("expected CA-constrained request to select matching chain")
	}
}

func TestFindTLSCertificateRequiresClientAuthEKU(t *testing.T) {
	_, _, leafCert, leafKey := newTestChain(t, "Test CA A", false)
	store := &testStore{
		idents: []Identity{
			&testIdentity{cert: leafCert, signer: leafKey},
		},
	}

	if _, err := FindTLSCertificate(context.Background(), store, SelectOptions{RequireClientAuthEKU: true}); err == nil {
		t.Fatal("expected non-client-auth certificate to be rejected")
	}
}

func TestFindTLSCertificateClosesDiscardedSignerCandidates(t *testing.T) {
	_, _, certA, keyA := newTestChain(t, "Test CA A", true)
	_, _, certB, keyB := newTestChain(t, "Test CA B", true)
	_, _, certC, keyC := newTestChain(t, "Test CA C", true)

	var closeA, closeB, closeC int
	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:   certA,
				signer: &testCloseableSigner{Signer: keyA, closeCalls: &closeA},
				info:   testIdentityInfo{backend: BackendPKCS11, hardware: false},
			},
			&testIdentity{
				cert:   certB,
				signer: &testCloseableSigner{Signer: keyB, closeCalls: &closeB},
				info:   testIdentityInfo{backend: BackendPKCS11, hardware: true},
			},
			&testIdentity{
				cert:   certC,
				signer: &testCloseableSigner{Signer: keyC, closeCalls: &closeC},
				info:   testIdentityInfo{backend: BackendPKCS11, hardware: false},
			},
		},
	}

	got, err := FindTLSCertificate(context.Background(), store, SelectOptions{PreferHardwareBacked: true})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Leaf == nil || got.Leaf.SerialNumber.Cmp(certB.SerialNumber) != 0 {
		t.Fatal("expected hardware-backed identity to win")
	}
	if closeA != 1 {
		t.Fatalf("expected replaced candidate signer to be closed once, got %d", closeA)
	}
	if closeB != 0 {
		t.Fatalf("expected winning candidate signer to remain open, got %d closes", closeB)
	}
	if closeC != 1 {
		t.Fatalf("expected lower-ranked candidate signer to be closed once, got %d", closeC)
	}
}

func TestFindTLSCertificateClosesSignerRejectedByCertificateRequest(t *testing.T) {
	ca, _, leaf, key := newTestChain(t, "Test CA A", true)
	var closes int

	store := &testStore{
		idents: []Identity{
			&testIdentity{
				cert:   leaf,
				chain:  []*x509.Certificate{leaf, ca},
				signer: &testCloseableSigner{Signer: key, closeCalls: &closes},
			},
		},
	}

	_, err := findTLSCertificate(context.Background(), store, SelectOptions{}, &tls.CertificateRequestInfo{
		Version:          tls.VersionTLS13,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		AcceptableCAs:    [][]byte{[]byte("different-ca")},
	})
	if err == nil {
		t.Fatal("expected ErrIdentityNotFound")
	}
	if closes != 1 {
		t.Fatalf("expected rejected signer to be closed once, got %d", closes)
	}
}

func newTestChain(t *testing.T, caName string, clientAuth bool) (*x509.Certificate, crypto.Signer, *x509.Certificate, crypto.Signer) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: caName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ekus := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if clientAuth {
		ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject: pkix.Name{
			CommonName: "client.example.com",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(48 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: ekus,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return caCert, caKey, leafCert, leafKey
}
