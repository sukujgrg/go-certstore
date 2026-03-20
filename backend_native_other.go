//go:build (!darwin && !windows && !linux) || (darwin && !cgo) || (windows && !cgo)

package certstore

func currentNativeBackend() Backend {
	return ""
}
