//go:build (!darwin && !windows && !linux) || (darwin && !cgo) || (windows && !cgo)

package certstore

import (
	"fmt"
	"runtime"
)

// Open returns an error on unsupported platforms or when CGo is disabled.
func Open() (Store, error) {
	return nil, fmt.Errorf("certstore is not supported on %s (cgo may be required)", runtime.GOOS)
}
