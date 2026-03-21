//go:build (!darwin && !windows && !linux) || (darwin && !cgo) || (windows && !cgo)

package certstore

import (
	"fmt"
	"runtime"
)

// openNativeStore returns an error on unsupported platforms or when CGo is disabled.
func openNativeStore() (Store, error) {
	return nil, fmt.Errorf("%w: native backend is not supported on %s (cgo may be required)", ErrUnsupportedBackend, runtime.GOOS)
}
