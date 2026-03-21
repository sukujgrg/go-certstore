package certstore

import (
	"crypto"
	"crypto/x509"
	"testing"
)

func TestCapabilityStateString(t *testing.T) {
	if got := CapabilityUnknown.String(); got != "unknown" {
		t.Fatalf("CapabilityUnknown.String() = %q", got)
	}
	if got := CapabilityNo.String(); got != "no" {
		t.Fatalf("CapabilityNo.String() = %q", got)
	}
	if got := CapabilityYes.String(); got != "yes" {
		t.Fatalf("CapabilityYes.String() = %q", got)
	}
}

func TestIdentityCapabilityHelpersPreferTriState(t *testing.T) {
	_, _, cert, key := newTestChain(t, "Capability CA", true)
	ident := &testIdentity{
		cert:   cert,
		signer: key,
		info: testIdentityInfo{
			backend:          BackendDarwin,
			hardware:         false,
			hardwareState:    CapabilityUnknown,
			hardwareStateSet: true,
			loginState:       CapabilityUnknown,
			loginStateSet:    true,
		},
	}

	if got := identityHardwareBackedState(ident); got != CapabilityUnknown {
		t.Fatalf("identityHardwareBackedState() = %v, want %v", got, CapabilityUnknown)
	}
	if got := identityLoginRequiredState(ident); got != CapabilityUnknown {
		t.Fatalf("identityLoginRequiredState() = %v, want %v", got, CapabilityUnknown)
	}
}

func TestIdentityCapabilityHelpersFallbackToIdentityInfo(t *testing.T) {
	_, _, cert, key := newTestChain(t, "Fallback CA", true)
	ident := &testIdentity{
		cert:   cert,
		signer: key,
		info: testIdentityInfo{
			backend:  BackendPKCS11,
			hardware: true,
		},
	}

	if got := identityHardwareBackedState(ident); got != CapabilityYes {
		t.Fatalf("identityHardwareBackedState() = %v, want %v", got, CapabilityYes)
	}
	if got := identityLoginRequiredState(ident); got != CapabilityNo {
		t.Fatalf("identityLoginRequiredState() = %v, want %v", got, CapabilityNo)
	}
}

func TestIdentityCapabilityHelpersNoMetadata(t *testing.T) {
	_, _, cert, key := newTestChain(t, "No Metadata CA", true)
	ident := &noMetadataIdentity{cert: cert, signer: key}

	if got := identityHardwareBackedState(ident); got != CapabilityUnknown {
		t.Fatalf("identityHardwareBackedState() = %v, want %v", got, CapabilityUnknown)
	}
	if got := identityLoginRequiredState(ident); got != CapabilityUnknown {
		t.Fatalf("identityLoginRequiredState() = %v, want %v", got, CapabilityUnknown)
	}
}

type noMetadataIdentity struct {
	cert   *x509.Certificate
	signer crypto.Signer
}

func (i *noMetadataIdentity) Certificate() (*x509.Certificate, error) { return i.cert, nil }
func (i *noMetadataIdentity) CertificateChain() ([]*x509.Certificate, error) {
	return []*x509.Certificate{i.cert}, nil
}
func (i *noMetadataIdentity) Signer() (crypto.Signer, error) { return i.signer, nil }
func (i *noMetadataIdentity) Close()                         {}
