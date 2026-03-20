package certstore

import (
	"strings"
	"testing"
)

func TestIdentityInfoHelpers(t *testing.T) {
	_, _, cert, _ := newTestChain(t, "Helper CA", true)

	if got := identityLabelFromCert(cert); got != cert.Subject.CommonName {
		t.Fatalf("identityLabelFromCert() = %q, want %q", got, cert.Subject.CommonName)
	}

	if got := identityKeyTypeFromCert(cert); got != "ECDSA" {
		t.Fatalf("identityKeyTypeFromCert() = %q, want ECDSA", got)
	}

	uri := identityURIFromCert(BackendDarwin, cert)
	if !strings.HasPrefix(uri, "darwin-keychain:sha256=") {
		t.Fatalf("identityURIFromCert() = %q", uri)
	}
}
