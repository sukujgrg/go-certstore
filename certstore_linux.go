//go:build linux

package certstore

import "fmt"

// openNativeStore returns an error on Linux because there is no single
// standard native X.509 identity store to target here.
func openNativeStore(cfg Options) (Store, error) {
	if hasWindowsConfig(cfg) {
		return nil, fmt.Errorf("%w: windows certificate store options are only supported on windows", ErrUnsupportedBackend)
	}
	return nil, fmt.Errorf("%w: native linux X.509 identity store is not supported", ErrUnsupportedBackend)
}
