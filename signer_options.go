package certstore

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

func signerHash(opts crypto.SignerOpts) (crypto.Hash, error) {
	if opts == nil {
		return 0, fmt.Errorf("%w: signer options are required", ErrInvalidConfiguration)
	}
	return opts.HashFunc(), nil
}

func normalizePSSSaltLength(hash crypto.Hash, saltLength int) (uint, error) {
	switch saltLength {
	case rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash:
		return uint(hash.Size()), nil
	}
	if saltLength < 0 {
		return 0, fmt.Errorf("%w: invalid RSA-PSS salt length %d", ErrInvalidConfiguration, saltLength)
	}
	return uint(saltLength), nil
}
