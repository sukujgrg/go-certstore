//go:build !cgo

package certstore

import (
	"context"
	"fmt"
)

func openPKCS11Store(context.Context, Options) (Store, error) {
	return nil, fmt.Errorf("%w: backend %q requires cgo", ErrUnsupportedBackend, BackendPKCS11)
}
