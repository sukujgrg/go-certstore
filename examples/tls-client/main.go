// tls-client demonstrates local TLS client-certificate selection.
//
// It opens a certstore backend, applies FindTLSCertificate with the requested
// filters, and prints the selected certificate or rejection reasons for each
// candidate. It does not perform a real TLS handshake or connect to a server.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"

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

	selectOpts := certstore.SelectOptions{
		SubjectCN:            *subject,
		IssuerCN:             *issuer,
		RequireClientAuthEKU: true,
		PreferHardwareBacked: true,
	}

	if *backend == "auto" && *subject == "" && *issuer == "" {
		fmt.Fprintln(os.Stderr, "Refusing to auto-select a client certificate from the native store without -subject or -issuer.")
		fmt.Fprintln(os.Stderr, "Use examples/list-identities to inspect candidates, then rerun with a filter such as:")
		fmt.Fprintln(os.Stderr, "  go run . -backend auto -subject \"client.example.com\"")
		fmt.Fprintln(os.Stderr)
		explainIdentityRejections(openOpts, selectOpts)
		os.Exit(2)
	}

	ctx := context.Background()
	store, err := certstore.Open(ctx, openOpts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()

	cert, err := certstore.FindTLSCertificate(ctx, store, selectOpts)
	if err != nil {
		if err == certstore.ErrIdentityNotFound {
			explainIdentityRejections(openOpts, selectOpts)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if cert == nil || cert.Leaf == nil {
		fmt.Fprintln(os.Stderr, "no client certificate selected")
		os.Exit(1)
	}

	fmt.Println("Selected client certificate:")
	fmt.Printf("  Subject:     %s\n", cert.Leaf.Subject.CommonName)
	fmt.Printf("  Issuer:      %s\n", cert.Leaf.Issuer.CommonName)
	fmt.Printf("  Not Before:  %s\n", cert.Leaf.NotBefore.Format("2006-01-02 15:04:05Z07:00"))
	fmt.Printf("  Not After:   %s\n", cert.Leaf.NotAfter.Format("2006-01-02 15:04:05Z07:00"))
	fmt.Printf("  Client Auth: %s\n", clientAuthSummary(cert.Leaf))
	fmt.Printf("  Chain Len:   %d\n", len(cert.Certificate))
	fmt.Println("  Chain:")
	for i, raw := range cert.Certificate {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			fmt.Printf("    [%d] <parse error: %v>\n", i, err)
			continue
		}
		fmt.Printf("    [%d] %s -> %s\n", i, parsed.Subject.CommonName, parsed.Issuer.CommonName)
	}
	fmt.Println("See examples/mtls-source for the recommended Open + NewClientCertificateSource + tls.Config pattern.")
}

func explainIdentityRejections(openOpts []certstore.Option, selectOpts certstore.SelectOptions) {
	ctx := context.Background()
	store, err := certstore.Open(ctx, openOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not inspect identities after selection failure: %v\n", err)
		return
	}
	defer store.Close()

	idents, err := store.Identities(ctx)
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
	cert, err := ident.Certificate(context.Background())
	if err != nil {
		fmt.Fprintf(out, "- identity rejected: certificate unavailable: %v\n", err)
		return
	}

	label := cert.Subject.CommonName
	backend := ""
	keyType := ""
	uri := ""
	hardware := certstore.CapabilityUnknown.String()
	login := certstore.CapabilityUnknown.String()
	if info, ok := ident.(certstore.IdentityInfo); ok {
		if info.Label() != "" {
			label = info.Label()
		}
		backend = string(info.Backend())
		keyType = info.KeyType()
		uri = info.URI()
	}
	if capability, ok := ident.(certstore.IdentityCapabilityInfo); ok {
		hardware = capability.HardwareBackedState().String()
		login = capability.LoginRequiredState().String()
	} else if info, ok := ident.(certstore.IdentityInfo); ok {
		if info.IsHardwareBacked() {
			hardware = certstore.CapabilityYes.String()
		} else {
			hardware = certstore.CapabilityNo.String()
		}
		if info.RequiresLogin() {
			login = certstore.CapabilityYes.String()
		} else {
			login = certstore.CapabilityNo.String()
		}
	}

	fmt.Fprintf(out, "- %s", label)
	if backend != "" {
		fmt.Fprintf(out, " [%s]", backend)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  subject:     %s\n", cert.Subject.CommonName)
	fmt.Fprintf(out, "  issuer:      %s\n", cert.Issuer.CommonName)
	if keyType != "" {
		fmt.Fprintf(out, "  key type:    %s\n", keyType)
	}
	fmt.Fprintf(out, "  not after:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05Z07:00"))
	fmt.Fprintf(out, "  client auth: %s\n", clientAuthSummary(cert))
	fmt.Fprintf(out, "  hardware:    %s\n", hardware)
	fmt.Fprintf(out, "  login:       %s\n", login)
	if uri != "" {
		fmt.Fprintf(out, "  uri:         %s\n", uri)
	}

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

	signer, err := ident.Signer(context.Background())
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

func clientAuthSummary(cert *x509.Certificate) string {
	if len(cert.ExtKeyUsage) == 0 {
		return "unspecified"
	}
	values := make([]string, 0, len(cert.ExtKeyUsage))
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageClientAuth:
			values = append(values, "client-auth")
		case x509.ExtKeyUsageServerAuth:
			values = append(values, "server-auth")
		case x509.ExtKeyUsageCodeSigning:
			values = append(values, "code-signing")
		case x509.ExtKeyUsageEmailProtection:
			values = append(values, "email-protection")
		case x509.ExtKeyUsageTimeStamping:
			values = append(values, "time-stamping")
		default:
			values = append(values, fmt.Sprintf("eku-%d", int(eku)))
		}
	}
	return strings.Join(values, ", ")
}
