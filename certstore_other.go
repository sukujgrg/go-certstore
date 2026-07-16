//go:build (!darwin && !windows && !linux) || (darwin && !cgo) || (windows && !cgo)

package certstore

import (
	"fmt"
	"runtime"
)

// openNativeStore returns an error on unsupported platforms or when CGo is disabled.
func openNativeStore(cfg Options) (Store, error) {
	if hasWindowsConfig(cfg) {
		return nil, fmt.Errorf("%w: windows certificate store options are only supported on windows", ErrUnsupportedBackend)
	}
	return nil, fmt.Errorf("%w: native backend is not supported on %s (cgo may be required)", ErrUnsupportedBackend, runtime.GOOS)
}
