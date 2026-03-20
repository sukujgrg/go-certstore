//go:build linux

package certstore

import "errors"

// openNativeStore returns an error on Linux because there is no standard
// system certificate store for client identities.
func openNativeStore() (Store, error) {
	return nil, errors.New("certstore is not supported on linux")
}
