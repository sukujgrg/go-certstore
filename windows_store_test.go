package certstore

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveWindowsStoreConfigDefaults(t *testing.T) {
	location, name, err := resolveWindowsStoreConfig(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if location != WindowsStoreCurrentUser {
		t.Fatalf("location = %q, want %q", location, WindowsStoreCurrentUser)
	}
	if name != "MY" {
		t.Fatalf("name = %q, want MY", name)
	}
}

func TestResolveWindowsStoreConfigCustom(t *testing.T) {
	location, name, err := resolveWindowsStoreConfig(Options{
		WindowsStoreLocation: WindowsStoreLocalMachine,
		WindowsStoreName:     " Root ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if location != WindowsStoreLocalMachine {
		t.Fatalf("location = %q", location)
	}
	if name != "Root" {
		t.Fatalf("name = %q, want Root", name)
	}
}

func TestResolveWindowsStoreConfigRejectsUnknownLocation(t *testing.T) {
	_, _, err := resolveWindowsStoreConfig(Options{
		WindowsStoreLocation: WindowsStoreLocation("service"),
	})
	if !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "windows store location") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOptionsWindowsStore(t *testing.T) {
	t.Run("windows options require windows-compatible backend", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:          BackendPKCS11,
			PKCS11Module:     "/tmp/module.so",
			WindowsStoreName: "MY",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("unknown windows location", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:              BackendWindows,
			WindowsStoreLocation: WindowsStoreLocation("service"),
		})
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("expected ErrInvalidConfiguration, got %v", err)
		}
	})

	t.Run("valid local machine my store", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:              BackendAuto,
			WindowsStoreLocation: WindowsStoreLocalMachine,
			WindowsStoreName:     "MY",
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestHasWindowsConfig(t *testing.T) {
	if hasWindowsConfig(Options{}) {
		t.Fatal("expected empty options to report no windows config")
	}
	if !hasWindowsConfig(Options{WindowsStoreLocation: WindowsStoreLocalMachine}) {
		t.Fatal("expected location to count as windows config")
	}
	if !hasWindowsConfig(Options{WindowsStoreName: "CA"}) {
		t.Fatal("expected store name to count as windows config")
	}
}

func TestResolveWindowsStoreConfigRejectsNULName(t *testing.T) {
	_, _, err := resolveWindowsStoreConfig(Options{
		WindowsStoreName: "MY\x00evil",
	})
	if !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUTF16PtrFromString(t *testing.T) {
	got, err := utf16PtrFromString("MY")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 || got[0] != 'M' || got[1] != 'Y' || got[len(got)-1] != 0 {
		t.Fatalf("unexpected utf16 encoding: %v", got)
	}
	if _, err := utf16PtrFromString("MY\x00"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected NUL rejection, got %v", err)
	}
}

func TestValidateOptionsRejectsWindowsWithTokenBackends(t *testing.T) {
	t.Run("windows with pkcs11", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:          BackendAuto,
			WindowsStoreName: "MY",
			PKCS11Module:     "/tmp/module.so",
		})
		if !errors.Is(err, ErrUnsupportedBackend) {
			t.Fatalf("expected ErrUnsupportedBackend, got %v", err)
		}
	})
	t.Run("windows with nss", func(t *testing.T) {
		err := validateOptions(Options{
			Backend:              BackendAuto,
			WindowsStoreLocation: WindowsStoreLocalMachine,
			NSSModule:            "/tmp/libsoftokn3.so",
			NSSProfileDir:        "/tmp/nss",
		})
		if !errors.Is(err, ErrUnsupportedBackend) {
			t.Fatalf("expected ErrUnsupportedBackend, got %v", err)
		}
	})
}
