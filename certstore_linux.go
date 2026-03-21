//go:build linux

package certstore

import "fmt"

// openNativeStore returns an error on Linux because there is no single
// standard native client-certificate identity store to target here.
func openNativeStore() (Store, error) {
	return nil, fmt.Errorf("%w: native linux client certificate store is not supported", ErrUnsupportedBackend)
}
