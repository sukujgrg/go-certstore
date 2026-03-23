//go:build cgo

package certstore

import "testing"

func TestWipeBytes(t *testing.T) {
	secret := []byte("secret")
	wipeBytes(secret)
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("secret[%d] = %d, want 0", i, b)
		}
	}
}
