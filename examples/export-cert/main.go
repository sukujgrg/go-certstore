package main

import (
	"encoding/pem"
	"flag"
	"log"
	"os"

	certstore "github.com/sukujgrg/go-certstore"
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

	openOpts := make([]certstore.Option, 0, 4)
	switch *backend {
	case "auto":
	case "pkcs11":
		openOpts = append(openOpts, certstore.WithBackend(certstore.BackendPKCS11))
	case "nss":
		openOpts = append(openOpts, certstore.WithBackend(certstore.BackendNSS))
	default:
		log.Fatalf("unsupported backend %q", *backend)
	}
	if *module != "" {
		if *backend == "nss" {
			openOpts = append(openOpts, certstore.WithNSSModule(*module))
		} else {
			openOpts = append(openOpts, certstore.WithPKCS11Module(*module))
		}
	}
	if *profile != "" {
		openOpts = append(openOpts, certstore.WithNSSProfileDir(*profile))
	}
	if *token != "" {
		openOpts = append(openOpts, certstore.WithPKCS11TokenLabel(*token))
	}
	pinValue := *pin
	if pinValue == "" {
		pinValue = os.Getenv("CERTSTORE_PIN")
	}
	if pinValue == "" {
		pinValue = os.Getenv("PKCS11_PIN")
	}
	if pinValue != "" {
		openOpts = append(openOpts, certstore.WithCredentialPrompt(func(certstore.PromptInfo) (string, error) {
			return pinValue, nil
		}))
	}

	store, err := certstore.Open(openOpts...)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	findOpts := certstore.FindIdentityOptions{
		SubjectCN: *subject,
		IssuerCN:  *issuer,
	}
	if *backend == "pkcs11" {
		findOpts.Backend = certstore.BackendPKCS11
	} else if *backend == "nss" {
		findOpts.Backend = certstore.BackendNSS
	}

	ident, err := certstore.FindIdentity(store, findOpts)
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
		certs, err := ident.CertificateChain()
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range certs {
			if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
				log.Fatal(err)
			}
		}
	} else {
		cert, err := ident.Certificate()
		if err != nil {
			log.Fatal(err)
		}
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			log.Fatal(err)
		}
	}
}
