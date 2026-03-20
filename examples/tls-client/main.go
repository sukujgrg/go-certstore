package main

import (
	"crypto/tls"
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
		log.Fatal(err)
	}
	if cert == nil || cert.Leaf == nil {
		log.Fatal("no client certificate selected")
	}

	fmt.Printf("Selected Subject: %s\n", cert.Leaf.Subject.CommonName)
	fmt.Printf("Selected Issuer:  %s\n", cert.Leaf.Issuer.CommonName)
	fmt.Printf("Chain Length:     %d\n", len(cert.Certificate))
}
