//go:build windows && cgo

package certstore

import (
	"errors"
	"syscall"
	"testing"
)

func TestClassifyWindowsStatusMapsSilentContext(t *testing.T) {
	err := classifyWindowsStatus("CryptAcquireCertificatePrivateKey", uint32(errNTESilentContext))
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("error = %v, want ErrLoginRequired", err)
	}
	if !errors.Is(err, errNTESilentContext) {
		t.Fatalf("error = %v, want errNTESilentContext", err)
	}
}

func TestClassifyWindowsStatusKeepsOperationalErrno(t *testing.T) {
	const code = syscall.Errno(2) // ERROR_FILE_NOT_FOUND
	err := classifyWindowsStatus("CertOpenStore", uint32(code))
	if errors.Is(err, ErrLoginRequired) {
		t.Fatalf("operational error misclassified: %v", err)
	}
	if !errors.Is(err, code) {
		t.Fatalf("error = %v, want errno %v", err, code)
	}
}
