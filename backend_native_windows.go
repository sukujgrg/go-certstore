//go:build windows && cgo

package certstore

func currentNativeBackend() Backend {
	return BackendWindows
}
