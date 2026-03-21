//go:build linux

package certstore

import "fmt"

// openNativeStore returns an error on Linux because there is no standard
// system certificate store for client identities.
func openNativeStore() (Store, error) {
	return nil, fmt.Errorf("%w: native linux client certificate store is not supported", ErrUnsupportedBackend)
}
