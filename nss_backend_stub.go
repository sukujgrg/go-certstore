//go:build !cgo

package certstore

import "fmt"

func openNSSStore(Options) (Store, error) {
	return nil, fmt.Errorf("%w: backend %q requires cgo", ErrUnsupportedBackend, BackendNSS)
}
