package certstore

import (
	"crypto/x509"
	"time"
)

// FindIdentityOptions controls identity filtering and selection outside of the
// TLS-specific helper path.
//
// FindIdentity returns at most one best-ranked identity from the matches, while
// FindIdentities returns all matches without ranking them down to a single
// winner.
type FindIdentityOptions struct {
	Backend Backend

	SubjectCN string
	IssuerCN  string
	Label     string
	KeyType   string
	URI       string

	ValidOnly             bool
	RequireHardwareBacked bool
	RequireLogin          bool
	PreferHardwareBacked  bool

	Now time.Time
}

// FindIdentities returns identities that match the requested certificate and
// metadata filters. Non-matching identities are closed before returning.
//
// It returns all matches. Use FindIdentity if you want a single best-ranked
// identity instead.
func FindIdentities(store Store, opts FindIdentityOptions) ([]Identity, error) {
	idents, err := store.Identities()
	if err != nil {
		return nil, err
	}

	var matched []Identity
	for _, ident := range idents {
		ok, err := matchesIdentity(ident, opts)
		if err != nil || !ok {
			ident.Close()
			continue
		}
		matched = append(matched, ident)
	}
	if len(matched) == 0 {
		return nil, ErrIdentityNotFound
	}
	return matched, nil
}

// FindIdentity returns the best matching identity and closes the rest.
//
// If more than one identity matches, the current scoring gives a strong bonus
// to hardware-backed identities when PreferHardwareBacked is set, gives a
// smaller bonus to currently valid certificates, and also favors later expiry.
// This is a scoring heuristic, not a strict lexicographic ordering.
func FindIdentity(store Store, opts FindIdentityOptions) (Identity, error) {
	idents, err := FindIdentities(store, opts)
	if err != nil {
		return nil, err
	}

	var (
		best      Identity
		bestScore int
	)
	for _, ident := range idents {
		cert, err := ident.Certificate()
		if err != nil {
			ident.Close()
			continue
		}
		score := scoreIdentity(ident, cert, opts)
		if best == nil || score > bestScore {
			if best != nil {
				best.Close()
			}
			best = ident
			bestScore = score
			continue
		}
		ident.Close()
	}
	if best == nil {
		return nil, ErrIdentityNotFound
	}
	return best, nil
}

func matchesIdentity(ident Identity, opts FindIdentityOptions) (bool, error) {
	cert, err := ident.Certificate()
	if err != nil {
		return false, err
	}
	if !matchesIdentityCertificate(cert, opts) {
		return false, nil
	}

	if info, ok := ident.(IdentityInfo); ok {
		if opts.Backend != "" && opts.Backend != BackendAuto && info.Backend() != opts.Backend {
			return false, nil
		}
		if opts.Label != "" && info.Label() != opts.Label {
			return false, nil
		}
		if opts.KeyType != "" && info.KeyType() != opts.KeyType {
			return false, nil
		}
		if opts.URI != "" && info.URI() != opts.URI {
			return false, nil
		}
		if opts.RequireHardwareBacked && identityHardwareBackedState(ident) != CapabilityYes {
			return false, nil
		}
		if opts.RequireLogin && identityLoginRequiredState(ident) != CapabilityYes {
			return false, nil
		}
	} else if opts.Backend != "" && opts.Backend != BackendAuto {
		return false, nil
	} else if opts.Label != "" || opts.KeyType != "" || opts.URI != "" || opts.RequireHardwareBacked || opts.RequireLogin {
		return false, nil
	}

	return true, nil
}

func matchesIdentityCertificate(cert *x509.Certificate, opts FindIdentityOptions) bool {
	if opts.SubjectCN != "" && cert.Subject.CommonName != opts.SubjectCN {
		return false
	}
	if opts.IssuerCN != "" && cert.Issuer.CommonName != opts.IssuerCN {
		return false
	}
	if opts.ValidOnly {
		now := opts.Now
		if now.IsZero() {
			now = time.Now()
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return false
		}
	}
	return true
}

func scoreIdentity(ident Identity, cert *x509.Certificate, opts FindIdentityOptions) int {
	score := 0
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
		score += 100
	}
	if opts.PreferHardwareBacked {
		if identityHardwareBackedState(ident) == CapabilityYes {
			score += 1000
		}
	}
	score += int(cert.NotAfter.Sub(now).Hours() / 24)
	return score
}
