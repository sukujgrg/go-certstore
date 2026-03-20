//go:build darwin && cgo

package certstore

func currentNativeBackend() Backend {
	return BackendDarwin
}
