//go:build cgo

package certstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/sukujgrg/go-certstore/internal/pkcs11"
)

type fakeObjectFinder struct {
	initCalls  int
	findCalls  int
	finalCalls int
	batches    [][]pkcs11.ObjectHandle
	onFind     func(int)
}

func (f *fakeObjectFinder) FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
	f.initCalls++
	return nil
}

func (f *fakeObjectFinder) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	f.findCalls++
	if f.onFind != nil {
		f.onFind(f.findCalls)
	}
	if len(f.batches) == 0 {
		return nil, false, nil
	}
	batch := f.batches[0]
	f.batches = f.batches[1:]
	return batch, false, nil
}

func (f *fakeObjectFinder) FindObjectsFinal(pkcs11.SessionHandle) error {
	f.finalCalls++
	return nil
}

type fakeSlotReader struct {
	slots          []uint
	slotInfo       map[uint]pkcs11.SlotInfo
	tokenInfo      map[uint]pkcs11.TokenInfo
	onGetSlotInfo  func(uint)
	onGetTokenInfo func(uint)
}

func (f *fakeSlotReader) GetSlotList(bool) ([]uint, error) {
	return append([]uint(nil), f.slots...), nil
}

func (f *fakeSlotReader) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	if f.onGetSlotInfo != nil {
		f.onGetSlotInfo(slotID)
	}
	if info, ok := f.slotInfo[slotID]; ok {
		return info, nil
	}
	return pkcs11.SlotInfo{}, nil
}

func (f *fakeSlotReader) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	if f.onGetTokenInfo != nil {
		f.onGetTokenInfo(slotID)
	}
	if info, ok := f.tokenInfo[slotID]; ok {
		return info, nil
	}
	return pkcs11.TokenInfo{}, nil
}

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

func TestFindPKCS11ObjectsHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	finder := &fakeObjectFinder{}
	_, err := findPKCS11Objects(ctx, finder, 0, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if finder.initCalls != 0 {
		t.Fatalf("FindObjectsInit called %d times", finder.initCalls)
	}
}

func TestFindPKCS11ObjectsStopsDuringScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	finder := &fakeObjectFinder{
		batches: [][]pkcs11.ObjectHandle{{1}},
		onFind: func(call int) {
			if call == 1 {
				cancel()
			}
		},
	}

	_, err := findPKCS11Objects(ctx, finder, 0, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if finder.initCalls != 1 {
		t.Fatalf("FindObjectsInit called %d times", finder.initCalls)
	}
	if finder.findCalls != 1 {
		t.Fatalf("FindObjects called %d times", finder.findCalls)
	}
	if finder.finalCalls != 1 {
		t.Fatalf("FindObjectsFinal called %d times", finder.finalCalls)
	}
}

func TestSelectPKCS11SlotStopsDuringScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	reader := &fakeSlotReader{
		slots: []uint{1, 2},
		tokenInfo: map[uint]pkcs11.TokenInfo{
			1: {Label: "wrong"},
			2: {Label: "target"},
		},
		onGetTokenInfo: func(slotID uint) {
			if slotID == 1 {
				cancel()
			}
		},
	}

	_, _, _, err := selectPKCS11Slot(ctx, reader, nil, "target")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
