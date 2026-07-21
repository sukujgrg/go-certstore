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
	"os"
	"strings"
	"time"

	certstore "github.com/sukujgrg/go-certstore"
)

// ExampleOpen_pkcs11 shows the Linux/token Open path with an explicit PKCS#11
// module. On Linux there is no native backend, so callers must pass backend
// options like this instead of relying on Open(ctx) alone.
func ExampleOpen_pkcs11() {
	ctx := context.Background()
	store, err := certstore.Open(ctx,
		certstore.WithBackend(certstore.BackendPKCS11),
		certstore.WithPKCS11Module(os.Getenv("SOFTHSM2_MODULE")),
		certstore.WithPKCS11TokenLabel("go-certstore-test"),
		certstore.WithCredentialPrompt(func(certstore.PromptInfo) ([]byte, error) {
			return []byte(os.Getenv("PKCS11_PIN")), nil
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	idents, err := store.Identities(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, ident := range idents {
		ident.Close()
	}
}

// ExampleNewClientCertificateSource_mTLS demonstrates how to use go-certstore to find a client
// certificate by CN and issuer, then use it for mTLS. Keep the store and
// ClientCertificateSource open for the life of the TLS client so handshakes
// can reuse cached certificates/signers; previously returned certificates stay
// alive until source.Close(). The source also reuses the context provided here
// because tls.Config does not expose a per-handshake context.
func ExampleNewClientCertificateSource_mTLS() {
	ctx := context.Background()
	store, err := certstore.Open(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	source := certstore.NewClientCertificateSource(ctx, store, certstore.SelectOptions{
		SubjectCN:            "myhost.example.com",
		IssuerCN:             "My Issuing CA",
		RequireClientAuthEKU: true,
	})
	defer source.Close()

	tlsConfig := &tls.Config{
		GetClientCertificate: source.GetClientCertificate,
	}
	_ = tlsConfig // use with http.Transport, tls.Dial, etc.
}

// ExampleStore_Identities shows how to enumerate all identities in the store.
func ExampleStore_Identities() {
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

// ExampleFindIdentities demonstrates structured identity selection with
// FindIdentities. Prefer this when SubjectCN/IssuerCN/validity filters are
// enough; use FilterIdentities only for arbitrary certificate predicates.
func ExampleFindIdentities() {
	store, err := certstore.Open(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	idents, err := certstore.FindIdentities(context.Background(), store, certstore.FindIdentityOptions{
		IssuerCN:  "My Issuing CA",
		ValidOnly: true,
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

// ExampleFilterIdentities demonstrates FilterIdentities for custom certificate
// predicates that FindIdentityOptions cannot express.
func ExampleFilterIdentities() {
	store, err := certstore.Open(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	idents, err := certstore.FilterIdentities(context.Background(), store, func(cert *x509.Certificate) bool {
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

// ExampleFindIdentity_subjectCN demonstrates finding a certificate by subject CN and
// checking that its private key signer is reachable.
func ExampleFindIdentity_subjectCN() {
	store, err := certstore.Open(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	ident, err := certstore.FindIdentity(context.Background(), store, certstore.FindIdentityOptions{
		SubjectCN: "myhost.example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ident.Close()

	cert, err := ident.Certificate(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Subject:  CN=%s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer:   CN=%s\n", cert.Issuer.CommonName)
	fmt.Printf("Serial:   %s\n", cert.SerialNumber.Text(16))
	fmt.Printf("Validity: %s to %s\n",
		cert.NotBefore.Format(time.DateOnly),
		cert.NotAfter.Format(time.DateOnly),
	)

	signer, err := ident.Signer(context.Background())
	if err != nil {
		fmt.Printf("Key:      INACCESSIBLE (%v)\n", err)
		return
	}
	defer func() {
		if err := certstore.CloseSigner(signer); err != nil {
			log.Printf("close signer: %v", err)
		}
	}()
	fmt.Printf("Key:      OK\n")
}

// ExampleCloseSigner demonstrates obtaining a signer directly and releasing
// its resources explicitly when done.
func ExampleCloseSigner() {
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
	defer func() {
		if err := certstore.CloseSigner(signer); err != nil {
			log.Printf("close signer: %v", err)
		}
	}()

	digest := sha256.Sum256([]byte("example payload"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
}
