//go:build !cgo

package certstore

import (
	"context"
	"errors"
	"testing"
)

func TestOpenPKCS11WithoutCGO(t *testing.T) {
	_, err := Open(context.Background(),
		WithBackend(BackendPKCS11),
		WithPKCS11Module("/tmp/test-pkcs11.so"),
	)
	if !errors.Is(err, ErrUnsupportedBackend) {
		t.Fatalf("expected ErrUnsupportedBackend, got %v", err)
	}
}

func TestOpenNSSWithoutCGO(t *testing.T) {
	_, err := Open(context.Background(),
		WithBackend(BackendNSS),
		WithNSSModule("/tmp/libsoftokn3.so"),
		WithNSSProfileDir("/tmp/nssdb"),
	)
	if !errors.Is(err, ErrUnsupportedBackend) {
		t.Fatalf("expected ErrUnsupportedBackend, got %v", err)
	}
}
