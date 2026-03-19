//go:build linux

package certstore

import "errors"

// Open returns an error on Linux because there is no standard system
// certificate store for client identities.
func Open() (Store, error) {
	return nil, errors.New("certstore is not supported on linux")
}
