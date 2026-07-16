package certstore

import (
	"fmt"
	"strings"
	"unicode/utf16"
)

// WindowsStoreLocation selects the Windows certificate store location.
type WindowsStoreLocation string

const (
	// WindowsStoreCurrentUser opens a store under the current user
	// (Cert:\CurrentUser\...).
	WindowsStoreCurrentUser WindowsStoreLocation = "current-user"

	// WindowsStoreLocalMachine opens a store under the local machine
	// (Cert:\LocalMachine\...). Opening this location typically requires
	// elevated privileges depending on the store and machine policy.
	WindowsStoreLocalMachine WindowsStoreLocation = "local-machine"
)

func hasWindowsConfig(cfg Options) bool {
	return cfg.WindowsStoreLocation != "" || cfg.WindowsStoreName != ""
}

func resolveWindowsStoreConfig(cfg Options) (WindowsStoreLocation, string, error) {
	location := cfg.WindowsStoreLocation
	if location == "" {
		location = WindowsStoreCurrentUser
	}
	switch location {
	case WindowsStoreCurrentUser, WindowsStoreLocalMachine:
	default:
		return "", "", fmt.Errorf("%w: windows store location %q is unknown", ErrInvalidConfiguration, location)
	}

	name := strings.TrimSpace(cfg.WindowsStoreName)
	if name == "" {
		name = "MY"
	}
	if strings.IndexByte(name, 0) >= 0 {
		return "", "", fmt.Errorf("%w: windows store name contains NUL", ErrInvalidConfiguration)
	}
	return location, name, nil
}

// utf16PtrFromString converts s to a NUL-terminated UTF-16 buffer for Windows
// APIs that take LPCWSTR. Embedded NUL bytes are rejected.
func utf16PtrFromString(s string) ([]uint16, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, fmt.Errorf("%w: windows store name contains NUL", ErrInvalidConfiguration)
	}
	encoded := utf16.Encode([]rune(s))
	return append(encoded, 0), nil
}
