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
		backend = flag.String("backend", "auto", "backend: auto or pkcs11")
		module  = flag.String("module", "", "PKCS#11 module path")
		token   = flag.String("token", "", "PKCS#11 token label")
		pin     = flag.String("pin", "", "PKCS#11 user PIN")
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
