package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	certstore "github.com/sukujgrg/go-certstore"
)

func main() {
	var (
		backend = flag.String("backend", "auto", "backend: auto or pkcs11")
		module  = flag.String("module", "", "PKCS#11 module path")
		token   = flag.String("token", "", "PKCS#11 token label")
		pin     = flag.String("pin", "", "PKCS#11 user PIN")
		subject = flag.String("subject", "", "required subject CN")
		issuer  = flag.String("issuer", "", "required issuer CN")
	)
	flag.Parse()

	openOpts := make([]certstore.Option, 0, 4)
	switch *backend {
	case "auto":
	case "pkcs11":
		openOpts = append(openOpts, certstore.WithBackend(certstore.BackendPKCS11))
	default:
		log.Fatalf("unsupported backend %q", *backend)
	}
	if *module != "" {
		openOpts = append(openOpts, certstore.WithPKCS11Module(*module))
	}
	if *token != "" {
		openOpts = append(openOpts, certstore.WithPKCS11TokenLabel(*token))
	}
	if *pin != "" {
		openOpts = append(openOpts, certstore.WithPKCS11PINPrompt(func(certstore.PromptInfo) (string, error) {
			return *pin, nil
		}))
	} else if envPIN := os.Getenv("PKCS11_PIN"); envPIN != "" {
		openOpts = append(openOpts, certstore.WithPKCS11PINPrompt(func(certstore.PromptInfo) (string, error) {
			return envPIN, nil
		}))
	}

	getClientCertificate := certstore.GetClientCertificateFunc(openOpts, certstore.SelectOptions{
		SubjectCN:            *subject,
		IssuerCN:             *issuer,
		RequireClientAuthEKU: true,
		PreferHardwareBacked: true,
	})

	tlsConfig := &tls.Config{
		GetClientCertificate: getClientCertificate,
	}

	cert, err := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		if errors.Is(err, certstore.ErrIdentityNotFound) {
			explainIdentityRejections(openOpts, certstore.SelectOptions{
				SubjectCN:            *subject,
				IssuerCN:             *issuer,
				RequireClientAuthEKU: true,
				PreferHardwareBacked: true,
			})
		}
		log.Fatal(err)
	}
	if cert == nil || cert.Leaf == nil {
		log.Fatal("no client certificate selected")
	}

	fmt.Printf("Selected Subject: %s\n", cert.Leaf.Subject.CommonName)
	fmt.Printf("Selected Issuer:  %s\n", cert.Leaf.Issuer.CommonName)
	fmt.Printf("Chain Length:     %d\n", len(cert.Certificate))
}

func explainIdentityRejections(openOpts []certstore.Option, selectOpts certstore.SelectOptions) {
	store, err := certstore.Open(openOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not inspect identities after selection failure: %v\n", err)
		return
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not enumerate identities after selection failure: %v\n", err)
		return
	}
	if len(idents) == 0 {
		fmt.Fprintln(os.Stderr, "No identities were found in the selected backend.")
		return
	}

	fmt.Fprintln(os.Stderr, "No matching client certificate was found. Candidate analysis:")
	for _, ident := range idents {
		describeIdentity(os.Stderr, ident, selectOpts)
		ident.Close()
	}
}

func describeIdentity(out *os.File, ident certstore.Identity, selectOpts certstore.SelectOptions) {
	cert, err := ident.Certificate()
	if err != nil {
		fmt.Fprintf(out, "- identity rejected: certificate unavailable: %v\n", err)
		return
	}

	label := cert.Subject.CommonName
	backend := ""
	if info, ok := ident.(certstore.IdentityInfo); ok {
		if info.Label() != "" {
			label = info.Label()
		}
		backend = string(info.Backend())
	}

	fmt.Fprintf(out, "- %s", label)
	if backend != "" {
		fmt.Fprintf(out, " [%s]", backend)
	}
	fmt.Fprintln(out)

	reasons := rejectionReasons(ident, cert, selectOpts)
	if len(reasons) == 0 {
		fmt.Fprintln(out, "  rejected: no specific local mismatch found")
		return
	}
	for _, reason := range reasons {
		fmt.Fprintf(out, "  rejected: %s\n", reason)
	}
}

func rejectionReasons(ident certstore.Identity, cert *x509.Certificate, selectOpts certstore.SelectOptions) []string {
	reasons := make([]string, 0, 4)

	if selectOpts.SubjectCN != "" && cert.Subject.CommonName != selectOpts.SubjectCN {
		reasons = append(reasons, fmt.Sprintf("subject CN %q does not match %q", cert.Subject.CommonName, selectOpts.SubjectCN))
	}
	if selectOpts.IssuerCN != "" && cert.Issuer.CommonName != selectOpts.IssuerCN {
		reasons = append(reasons, fmt.Sprintf("issuer CN %q does not match %q", cert.Issuer.CommonName, selectOpts.IssuerCN))
	}
	if selectOpts.RequireClientAuthEKU && !hasClientAuthEKU(cert) {
		reasons = append(reasons, "certificate does not allow TLS client authentication")
	}

	signer, err := ident.Signer()
	if err != nil {
		reasons = append(reasons, fmt.Sprintf("private key signer unavailable: %v", err))
	} else {
		_ = certstore.CloseSigner(signer)
	}

	return reasons
}

func hasClientAuthEKU(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny || eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
