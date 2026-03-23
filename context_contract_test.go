package certstore

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
)

type contextAwareStore struct {
	t      *testing.T
	idents []Identity
}

func (s *contextAwareStore) Identities(ctx context.Context) ([]Identity, error) {
	s.t.Helper()
	if ctx == nil {
		s.t.Fatal("received nil context")
	}
	return s.idents, nil
}

func (s *contextAwareStore) Close() {}

type contextAwareIdentity struct {
	t      *testing.T
	cert   *x509.Certificate
	signer crypto.Signer
}

func (i *contextAwareIdentity) Certificate(ctx context.Context) (*x509.Certificate, error) {
	i.t.Helper()
	if ctx == nil {
		i.t.Fatal("Certificate received nil context")
	}
	return i.cert, nil
}

func (i *contextAwareIdentity) CertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	i.t.Helper()
	if ctx == nil {
		i.t.Fatal("CertificateChain received nil context")
	}
	return []*x509.Certificate{i.cert}, nil
}

func (i *contextAwareIdentity) Signer(ctx context.Context) (crypto.Signer, error) {
	i.t.Helper()
	if ctx == nil {
		i.t.Fatal("Signer received nil context")
	}
	return i.signer, nil
}

func (i *contextAwareIdentity) Close() {}

type countingIdentity struct {
	cert             *x509.Certificate
	signer           crypto.Signer
	closeCalls       int
	certificateCalls int
	onCertificate    func(int)
}

func (i *countingIdentity) Certificate(context.Context) (*x509.Certificate, error) {
	i.certificateCalls++
	if i.onCertificate != nil {
		i.onCertificate(i.certificateCalls)
	}
	return i.cert, nil
}

func (i *countingIdentity) CertificateChain(context.Context) ([]*x509.Certificate, error) {
	return []*x509.Certificate{i.cert}, nil
}

func (i *countingIdentity) Signer(context.Context) (crypto.Signer, error) {
	return i.signer, nil
}

func (i *countingIdentity) Close() {
	i.closeCalls++
}

func TestFilterIdentitiesClosesEachIdentityOnceWhenContextCanceled(t *testing.T) {
	_, _, certA, signerA := newTestChain(t, "Filter Cancel CA A", true)
	_, _, certB, signerB := newTestChain(t, "Filter Cancel CA B", true)

	ctx, cancel := context.WithCancel(context.Background())
	idA := &countingIdentity{
		cert:   certA,
		signer: signerA,
		onCertificate: func(call int) {
			if call == 1 {
				cancel()
			}
		},
	}
	idB := &countingIdentity{cert: certB, signer: signerB}

	store := &contextAwareStore{t: t, idents: []Identity{idA, idB}}
	_, err := filterStoreIdentities(ctx, store, func(*x509.Certificate) bool { return true })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if idA.closeCalls != 1 {
		t.Fatalf("first identity closed %d times", idA.closeCalls)
	}
	if idB.closeCalls != 1 {
		t.Fatalf("second identity closed %d times", idB.closeCalls)
	}
}

func TestFindIdentitiesClosesEachIdentityOnceWhenContextCanceled(t *testing.T) {
	_, _, certA, signerA := newTestChain(t, "Find Cancel CA A", true)
	_, _, certB, signerB := newTestChain(t, "Find Cancel CA B", true)

	ctx, cancel := context.WithCancel(context.Background())
	idA := &countingIdentity{
		cert:   certA,
		signer: signerA,
		onCertificate: func(call int) {
			if call == 1 {
				cancel()
			}
		},
	}
	idB := &countingIdentity{cert: certB, signer: signerB}

	store := &contextAwareStore{t: t, idents: []Identity{idA, idB}}
	_, err := FindIdentities(ctx, store, FindIdentityOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if idA.closeCalls != 1 {
		t.Fatalf("first identity closed %d times", idA.closeCalls)
	}
	if idB.closeCalls != 1 {
		t.Fatalf("second identity closed %d times", idB.closeCalls)
	}
}

func TestFindIdentityClosesEachIdentityOnceWhenContextCanceled(t *testing.T) {
	_, _, certA, signerA := newTestChain(t, "Find Best Cancel CA A", true)
	_, _, certB, signerB := newTestChain(t, "Find Best Cancel CA B", true)

	ctx, cancel := context.WithCancel(context.Background())
	idA := &countingIdentity{
		cert:   certA,
		signer: signerA,
		onCertificate: func(call int) {
			if call == 2 {
				cancel()
			}
		},
	}
	idB := &countingIdentity{cert: certB, signer: signerB}

	store := &contextAwareStore{t: t, idents: []Identity{idA, idB}}
	_, err := FindIdentity(ctx, store, FindIdentityOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if idA.closeCalls != 1 {
		t.Fatalf("first identity closed %d times", idA.closeCalls)
	}
	if idB.closeCalls != 1 {
		t.Fatalf("second identity closed %d times", idB.closeCalls)
	}
}

func TestFindIdentitiesMatchesCapabilityOnlyIdentity(t *testing.T) {
	_, _, cert, signer := newTestChain(t, "Capability Only CA", true)

	ident := &capabilityOnlyIdentity{
		countingIdentity: countingIdentity{cert: cert, signer: signer},
		hardwareState:    CapabilityYes,
		loginState:       CapabilityYes,
	}
	store := &contextAwareStore{t: t, idents: []Identity{ident}}

	idents, err := FindIdentities(context.Background(), store, FindIdentityOptions{
		RequireHardwareBacked: true,
		RequireLogin:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(idents) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(idents))
	}
	idents[0].Close()
}

type capabilityOnlyIdentity struct {
	countingIdentity
	hardwareState CapabilityState
	loginState    CapabilityState
}

func (i *capabilityOnlyIdentity) HardwareBackedState() CapabilityState {
	return i.hardwareState
}

func (i *capabilityOnlyIdentity) LoginRequiredState() CapabilityState {
	return i.loginState
}

func TestNormalizeContextReturnsBackgroundForNil(t *testing.T) {
	if normalizeContext(nil) == nil {
		t.Fatal("expected background context for nil input")
	}
}

func TestFindIdentityNormalizesNilContext(t *testing.T) {
	_, _, cert, signer := newTestChain(t, "Context CA", true)

	store := &contextAwareStore{
		t: t,
		idents: []Identity{
			&contextAwareIdentity{t: t, cert: cert, signer: signer},
		},
	}

	ident, err := FindIdentity(nil, store, FindIdentityOptions{
		SubjectCN: cert.Subject.CommonName,
	})
	if err != nil {
		t.Fatal(err)
	}
	ident.Close()
}

func TestFindIdentitiesNormalizesNilContext(t *testing.T) {
	_, _, cert, signer := newTestChain(t, "Context CA", true)

	store := &contextAwareStore{
		t: t,
		idents: []Identity{
			&contextAwareIdentity{t: t, cert: cert, signer: signer},
		},
	}

	idents, err := FindIdentities(nil, store, FindIdentityOptions{
		SubjectCN: cert.Subject.CommonName,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ident := range idents {
		ident.Close()
	}
}

func TestFindTLSCertificateNormalizesNilContext(t *testing.T) {
	_, _, cert, signer := newTestChain(t, "TLS Context CA", true)

	store := &contextAwareStore{
		t: t,
		idents: []Identity{
			&contextAwareIdentity{t: t, cert: cert, signer: signer},
		},
	}

	got, err := FindTLSCertificate(nil, store, SelectOptions{
		SubjectCN:            cert.Subject.CommonName,
		RequireClientAuthEKU: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Leaf == nil {
		t.Fatal("expected TLS certificate")
	}
}

func TestGetClientCertificateFuncReusesSuppliedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	getClientCertificate := GetClientCertificateFunc(ctx, nil, SelectOptions{})

	cancel()

	_, err := getClientCertificate(&tls.CertificateRequestInfo{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
