package certstore

import "testing"

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
