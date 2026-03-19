package certstore_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"

	certstore "github.com/sukujgrg/go-certstore"
)

// Example_mTLS demonstrates how to use go-certstore to find a client
// certificate by CN and issuer, then use it for mTLS.
func Example_mTLS() {
	tlsConfig := &tls.Config{
		GetClientCertificate: getCertificate("myhost.example.com", "My Issuing CA"),
	}
	_ = tlsConfig // use with http.Transport, tls.Dial, etc.
}

// getCertificate returns a callback suitable for tls.Config.GetClientCertificate.
// It opens the system cert store, finds a valid cert matching the given CN and
// issuer, and returns it along with a crypto.Signer for the private key.
func getCertificate(cn, issuer string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		store, err := certstore.Open()
		if err != nil {
			return nil, fmt.Errorf("opening cert store: %w", err)
		}
		defer store.Close()

		idents, err := store.Identities()
		if err != nil {
			return nil, fmt.Errorf("listing identities: %w", err)
		}

		for _, ident := range idents {
			defer ident.Close()

			cert, err := ident.Certificate()
			if err != nil {
				continue
			}
			if cert.Subject.CommonName != cn {
				continue
			}
			if time.Now().After(cert.NotAfter) {
				continue // expired
			}
			if cert.Issuer.CommonName != issuer {
				continue
			}

			signer, err := ident.Signer()
			if err != nil {
				return nil, fmt.Errorf("getting signer: %w", err)
			}

			return &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  signer,
			}, nil
		}

		return nil, fmt.Errorf("no valid certificate found for CN=%s, Issuer=%s", cn, issuer)
	}
}

// Example_listCertificates shows how to enumerate all identities in the store.
func Example_listCertificates() {
	store, err := certstore.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		log.Fatal(err)
	}

	for _, ident := range idents {
		defer ident.Close()

		cert, err := ident.Certificate()
		if err != nil {
			continue
		}
		fmt.Printf("CN=%s  Issuer=%s  NotAfter=%s\n",
			cert.Subject.CommonName,
			cert.Issuer.CommonName,
			cert.NotAfter.Format(time.DateOnly),
		)
	}
}

// Example_filterIdentities demonstrates using FilterIdentities to find
// specific certificates by CN, issuer, or expiry.
func Example_filterIdentities() {
	// Find all valid certs issued by a specific CA
	idents, err := certstore.FilterIdentities(func(cert *x509.Certificate) bool {
		return cert.Issuer.CommonName == "My Issuing CA" &&
			time.Now().Before(cert.NotAfter)
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, ident := range idents {
		defer ident.Close()
		cert, _ := ident.Certificate()
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		fmt.Printf("CN=%s  Expires in %d days\n", cert.Subject.CommonName, days)
	}
}

// Example_filterByCN demonstrates finding a certificate by subject CN.
func Example_filterByCN() {
	idents, err := certstore.FilterIdentities(func(cert *x509.Certificate) bool {
		return cert.Subject.CommonName == "myhost.example.com"
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, ident := range idents {
		defer ident.Close()
		cert, _ := ident.Certificate()

		fmt.Printf("Subject:  CN=%s\n", cert.Subject.CommonName)
		fmt.Printf("Issuer:   CN=%s\n", cert.Issuer.CommonName)
		fmt.Printf("Serial:   %s\n", cert.SerialNumber.Text(16))
		fmt.Printf("Validity: %s to %s\n",
			cert.NotBefore.Format(time.DateOnly),
			cert.NotAfter.Format(time.DateOnly),
		)

		// Check if private key is accessible
		_, err := ident.Signer()
		if err != nil {
			fmt.Printf("Key:      INACCESSIBLE (%v)\n", err)
		} else {
			fmt.Printf("Key:      OK\n")
		}
	}
}

// Example_filterSubstring demonstrates substring matching on CN.
func Example_filterSubstring() {
	idents, err := certstore.FilterIdentities(func(cert *x509.Certificate) bool {
		return strings.Contains(cert.Subject.CommonName, "example.com") &&
			time.Now().Before(cert.NotAfter)
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d matching certificates\n", len(idents))
	for _, ident := range idents {
		ident.Close()
	}
}
