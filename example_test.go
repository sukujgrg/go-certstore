package certstore_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"

	certstore "github.com/sukujgrg/go-certstore"
)

// Example_mTLS demonstrates how to use go-certstore to find a client
// certificate by CN and issuer, then use it for mTLS. The callback reuses the
// context provided here on each handshake because tls.Config does not expose a
// per-handshake context.
func Example_mTLS() {
	tlsConfig := &tls.Config{
		GetClientCertificate: certstore.GetClientCertificateFunc(context.Background(), nil, certstore.SelectOptions{
			SubjectCN:            "myhost.example.com",
			IssuerCN:             "My Issuing CA",
			RequireClientAuthEKU: true,
		}),
	}
	_ = tlsConfig // use with http.Transport, tls.Dial, etc.
}

// getCertificate returns a callback suitable for tls.Config.GetClientCertificate.
// It wraps the higher-level helper for callers who prefer a local function and
// intentionally captures one long-lived context for later callback reuse.
func getCertificate(cn, issuer string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return certstore.GetClientCertificateFunc(context.Background(), nil, certstore.SelectOptions{
		SubjectCN:            cn,
		IssuerCN:             issuer,
		RequireClientAuthEKU: true,
	})
}

// Example_listCertificates shows how to enumerate all identities in the store.
func Example_listCertificates() {
	store, err := certstore.Open(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	idents, err := store.Identities(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	for _, ident := range idents {
		defer ident.Close()

		cert, err := ident.Certificate(context.Background())
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
	idents, err := certstore.FilterIdentities(context.Background(), func(cert *x509.Certificate) bool {
		return cert.Issuer.CommonName == "My Issuing CA" &&
			time.Now().Before(cert.NotAfter)
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, ident := range idents {
		defer ident.Close()
		cert, _ := ident.Certificate(context.Background())
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		fmt.Printf("CN=%s  Expires in %d days\n", cert.Subject.CommonName, days)
	}
}

// Example_filterByCN demonstrates finding a certificate by subject CN.
func Example_filterByCN() {
	idents, err := certstore.FilterIdentities(context.Background(), func(cert *x509.Certificate) bool {
		return cert.Subject.CommonName == "myhost.example.com"
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, ident := range idents {
		defer ident.Close()
		cert, _ := ident.Certificate(context.Background())

		fmt.Printf("Subject:  CN=%s\n", cert.Subject.CommonName)
		fmt.Printf("Issuer:   CN=%s\n", cert.Issuer.CommonName)
		fmt.Printf("Serial:   %s\n", cert.SerialNumber.Text(16))
		fmt.Printf("Validity: %s to %s\n",
			cert.NotBefore.Format(time.DateOnly),
			cert.NotAfter.Format(time.DateOnly),
		)

		// Check if private key is accessible
		_, err := ident.Signer(context.Background())
		if err != nil {
			fmt.Printf("Key:      INACCESSIBLE (%v)\n", err)
		} else {
			fmt.Printf("Key:      OK\n")
		}
	}
}

// Example_filterSubstring demonstrates substring matching on CN.
func Example_filterSubstring() {
	idents, err := certstore.FilterIdentities(context.Background(), func(cert *x509.Certificate) bool {
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

// Example_signerCleanup demonstrates obtaining a signer directly and releasing
// its resources explicitly when done.
func Example_signerCleanup() {
	store, err := certstore.Open(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	ident, err := certstore.FindIdentity(context.Background(), store, certstore.FindIdentityOptions{
		SubjectCN: "myhost.example.com",
		ValidOnly: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ident.Close()

	signer, err := ident.Signer(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer certstore.CloseSigner(signer)

	digest := sha256.Sum256([]byte("example payload"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
}
