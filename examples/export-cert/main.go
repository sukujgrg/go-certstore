// export-cert writes a selected certificate or certificate chain in PEM form.
package main

import (
	"context"
	"encoding/pem"
	"flag"
	"log"
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
		subject = flag.String("subject", "", "subject CN to match")
		issuer  = flag.String("issuer", "", "issuer CN to match")
		chain   = flag.Bool("chain", false, "export full certificate chain")
		outFile = flag.String("out", "", "output file (default: stdout)")
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
		log.Fatal(err)
	}

	ctx := context.Background()
	store, err := certstore.Open(ctx, openOpts...)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	findOpts := certstore.FindIdentityOptions{
		Backend:   cli.FindBackend(*backend),
		SubjectCN: *subject,
		IssuerCN:  *issuer,
	}

	ident, err := certstore.FindIdentity(ctx, store, findOpts)
	if err != nil {
		log.Fatal(err)
	}
	defer ident.Close()

	out := os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		out = f
	}

	if *chain {
		certs, err := ident.CertificateChain(ctx)
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range certs {
			if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
				log.Fatal(err)
			}
		}
	} else {
		cert, err := ident.Certificate(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			log.Fatal(err)
		}
	}
}
