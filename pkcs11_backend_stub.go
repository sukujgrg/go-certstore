//go:build !cgo

package certstore

import "fmt"

func openPKCS11Store(Options) (Store, error) {
	return nil, fmt.Errorf("%w: backend %q requires cgo", ErrUnsupportedBackend, BackendPKCS11)
}
