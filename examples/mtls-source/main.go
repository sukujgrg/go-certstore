// mtls-source demonstrates the recommended long-lived store + ClientCertificateSource
// pattern for TLS client authentication.
//
// It opens a certstore backend once, builds a tls.Config backed by
// NewClientCertificateSource, simulates two GetClientCertificate callbacks to
// show cache reuse, then closes the source and store. It does not dial a
// remote server.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"

	certstore "github.com/sukujgrg/go-certstore"
	"github.com/sukujgrg/go-certstore/examples/internal/cli"
)

func main() {
	var (
		backend = flag.String("backend", "auto", "backend: auto, pkcs11, or nss")
		module  = flag.String("module", "", "module path (PKCS#11 module or NSS softokn3)")
		profile = flag.String("profile", "", "NSS profile/database directory")
		token   = flag.String("token", "", "PKCS#11 token label")
		pin     = flag.String("pin", "", "token or database credential")
		subject = flag.String("subject", "", "required subject CN")
		issuer  = flag.String("issuer", "", "required issuer CN")
	)
	flag.Parse()

	openOpts, err := cli.OpenOptions(cli.OpenConfig{
		Backend: *backend,
		Module:  *module,
		Profile: *profile,
		Token:   *token,
		PIN:     *pin,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if *backend == "auto" && *subject == "" && *issuer == "" {
		fmt.Fprintln(os.Stderr, "Refusing to auto-select a client certificate from the native store without -subject or -issuer.")
		fmt.Fprintln(os.Stderr, "Use examples/list-identities to inspect candidates, then rerun with a filter such as:")
		fmt.Fprintln(os.Stderr, "  go run ./examples/mtls-source -backend auto -subject \"client.example.com\"")
		os.Exit(2)
	}

	ctx := context.Background()
	store, err := certstore.Open(ctx, openOpts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	source := certstore.NewClientCertificateSource(ctx, store, certstore.SelectOptions{
		SubjectCN:            *subject,
		IssuerCN:             *issuer,
		RequireClientAuthEKU: true,
		PreferHardwareBacked: true,
	})
	defer source.Close()

	tlsConfig := &tls.Config{
		GetClientCertificate: source.GetClientCertificate,
		MinVersion:           tls.VersionTLS12,
	}

	// Advertise every scheme this package may attach to a tls.Certificate so
	// the simulated request does not reject otherwise-supported RSA, ECDSA, or
	// Ed25519 client certificates.
	req := &tls.CertificateRequestInfo{
		SignatureSchemes: []tls.SignatureScheme{
			tls.PSSWithSHA256,
			tls.PSSWithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA256,
			tls.PKCS1WithSHA384,
			tls.PKCS1WithSHA512,
			tls.PKCS1WithSHA1,
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
			tls.ECDSAWithSHA1,
			tls.Ed25519,
		},
	}

	first, err := tlsConfig.GetClientCertificate(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if first == nil || first.Leaf == nil {
		fmt.Fprintln(os.Stderr, "no client certificate selected")
		os.Exit(1)
	}

	second, err := tlsConfig.GetClientCertificate(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Recommended mTLS setup:")
	fmt.Println("  1. Open the store once with explicit backend options")
	fmt.Println("  2. Create NewClientCertificateSource(ctx, store, selectOpts)")
	fmt.Println("  3. Set tls.Config.GetClientCertificate = source.GetClientCertificate")
	fmt.Println("  4. defer source.Close() and defer store.Close()")
	fmt.Println()
	fmt.Println("Selected client certificate:")
	fmt.Printf("  Subject:    %s\n", first.Leaf.Subject.CommonName)
	fmt.Printf("  Issuer:     %s\n", first.Leaf.Issuer.CommonName)
	fmt.Printf("  Not After:  %s\n", first.Leaf.NotAfter.Format("2006-01-02 15:04:05Z07:00"))
	fmt.Printf("  Chain Len:  %d\n", len(first.Certificate))
	if second == first {
		fmt.Println("  Cache:      reused the same tls.Certificate on the second callback")
	} else {
		fmt.Println("  Cache:      returned a different tls.Certificate on the second callback")
	}
	fmt.Println()
	fmt.Println("Wire tlsConfig into http.Transport.TLSClientConfig or tls.Dial for a real handshake.")
}
