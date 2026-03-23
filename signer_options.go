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

func normalizePSSSaltLength(pub *rsa.PublicKey, hash crypto.Hash, saltLength int) (uint, error) {
	switch saltLength {
	case rsa.PSSSaltLengthAuto:
		maxSaltLength, err := maxPSSSaltLength(pub, hash)
		if err != nil {
			return 0, err
		}
		return uint(maxSaltLength), nil
	case rsa.PSSSaltLengthEqualsHash:
		return uint(hash.Size()), nil
	}
	if saltLength < 0 {
		return 0, fmt.Errorf("%w: invalid RSA-PSS salt length %d", ErrInvalidConfiguration, saltLength)
	}
	return uint(saltLength), nil
}

func maxPSSSaltLength(pub *rsa.PublicKey, hash crypto.Hash) (int, error) {
	if pub == nil || pub.N == nil {
		return 0, fmt.Errorf("%w: rsa public key is required", ErrInvalidConfiguration)
	}

	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	saltLength := emLen - hash.Size() - 2
	if saltLength < 0 {
		return 0, fmt.Errorf("%w: rsa key too small for %v RSA-PSS salt length", ErrMechanismUnsupported, hash)
	}
	return saltLength, nil
}
