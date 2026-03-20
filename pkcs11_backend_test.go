//go:build cgo

package certstore

import (
	"crypto/x509"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestPKCS11SignatureMechanismRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	mech, input, err := pkcs11SignatureMechanism(&key.PublicKey, make([]byte, crypto.SHA256.Size()), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if mech.Mechanism != pkcs11.CKM_RSA_PKCS {
		t.Fatalf("expected CKM_RSA_PKCS, got %d", mech.Mechanism)
	}
	if len(input) == crypto.SHA256.Size() {
		t.Fatal("expected PKCS#1 v1.5 input to include DigestInfo wrapper")
	}
}

func TestPKCS11SignatureMechanismRSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	digest := make([]byte, crypto.SHA256.Size())
	mech, input, err := pkcs11SignatureMechanism(&key.PublicKey, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mech.Mechanism != pkcs11.CKM_RSA_PKCS_PSS {
		t.Fatalf("expected CKM_RSA_PKCS_PSS, got %d", mech.Mechanism)
	}
	if len(input) != len(digest) {
		t.Fatal("expected RSA-PSS to sign the raw digest")
	}
}

func TestECDSARawToASN1(t *testing.T) {
	pub := &ecdsa.PublicKey{Curve: elliptic.P256()}
	raw := make([]byte, 64)
	raw[31] = 1
	raw[63] = 2

	der, err := ecdsaRawToASN1(raw, pub)
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		R, S int
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.R != 1 || parsed.S != 2 {
		t.Fatalf("unexpected signature values: %+v", parsed)
	}
}

func TestBuildCertificateChain(t *testing.T) {
	root := &x509.Certificate{
		Raw:          []byte{1},
		RawSubject:   []byte("root"),
		RawIssuer:    []byte("root"),
		SubjectKeyId: []byte{0x03},
		SerialNumber: big.NewInt(3),
	}
	intermediate := &x509.Certificate{
		Raw:            []byte{2},
		RawSubject:     []byte("intermediate"),
		RawIssuer:      []byte("root"),
		AuthorityKeyId: []byte{0x03},
		SubjectKeyId:   []byte{0x02},
		SerialNumber:   big.NewInt(2),
	}
	leaf := &x509.Certificate{
		Raw:            []byte{3},
		RawSubject:     []byte("leaf"),
		RawIssuer:      []byte("intermediate"),
		AuthorityKeyId: []byte{0x02},
		SerialNumber:   big.NewInt(1),
	}

	chain := buildCertificateChain(leaf, []*x509.Certificate{leaf, root, intermediate})
	if len(chain) != 3 {
		t.Fatalf("expected 3 certs in chain, got %d", len(chain))
	}
	if chain[1] != intermediate || chain[2] != root {
		t.Fatalf("unexpected chain order: %+v", chain)
	}
}
