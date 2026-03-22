package certstore

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ecdsaRawToASN1 converts a raw ECDSA signature (r || s) to ASN.1 DER
// encoding as expected by Go's crypto/ecdsa verification.
func ecdsaRawToASN1(raw []byte, pub *ecdsa.PublicKey) ([]byte, error) {
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	if len(raw) != 2*keySize {
		return nil, fmt.Errorf("invalid ECDSA signature length: got %d, want %d", len(raw), 2*keySize)
	}

	type ecdsaSig struct {
		R, S *big.Int
	}

	r := new(big.Int).SetBytes(raw[:keySize])
	s := new(big.Int).SetBytes(raw[keySize:])

	return asn1.Marshal(ecdsaSig{R: r, S: s})
}
