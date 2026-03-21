package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	certstore "github.com/sukujgrg/go-certstore"
)

func main() {
	var (
		backend = flag.String("backend", "auto", "backend: auto, pkcs11, or nss")
		module  = flag.String("module", "", "module path (PKCS#11 module or NSS softokn3)")
		profile = flag.String("profile", "", "NSS profile/database directory")
		token   = flag.String("token", "", "PKCS#11 token label")
		pin     = flag.String("pin", "", "token or database PIN/password")
		subject = flag.String("subject", "", "filter by subject common name")
		issuer  = flag.String("issuer", "", "filter by issuer common name")
		valid   = flag.Bool("valid", false, "only show currently valid identities")
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
		ValidOnly: *valid,
	}
	if *backend == "pkcs11" {
		findOpts.Backend = certstore.BackendPKCS11
	} else if *backend == "nss" {
		findOpts.Backend = certstore.BackendNSS
	}

	idents, err := certstore.FindIdentities(store, findOpts)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		for _, ident := range idents {
			ident.Close()
		}
	}()

	for _, ident := range idents {
		cert, err := ident.Certificate()
		if err != nil {
			continue
		}
		info, _ := ident.(certstore.IdentityInfo)
		label := ""
		backendName := ""
		keyType := ""
		hardwareState := certstore.CapabilityUnknown.String()
		loginState := certstore.CapabilityUnknown.String()
		uri := ""
		if info != nil {
			label = info.Label()
			backendName = string(info.Backend())
			keyType = info.KeyType()
			uri = info.URI()
		}
		if capability, ok := ident.(certstore.IdentityCapabilityInfo); ok {
			hardwareState = capability.HardwareBackedState().String()
			loginState = capability.LoginRequiredState().String()
		} else if info != nil {
			if info.IsHardwareBacked() {
				hardwareState = certstore.CapabilityYes.String()
			} else {
				hardwareState = certstore.CapabilityNo.String()
			}
			if info.RequiresLogin() {
				loginState = certstore.CapabilityYes.String()
			} else {
				loginState = certstore.CapabilityNo.String()
			}
		}
		fmt.Printf("Label:     %s\n", label)
		fmt.Printf("Backend:   %s\n", backendName)
		fmt.Printf("Key Type:  %s\n", keyType)
		fmt.Printf("Hardware:  %s\n", hardwareState)
		fmt.Printf("Login:     %s\n", loginState)
		fmt.Printf("Subject:   %s\n", cert.Subject.CommonName)
		fmt.Printf("Issuer:    %s\n", cert.Issuer.CommonName)
		fmt.Printf("Not After: %s\n", cert.NotAfter.Format(time.RFC3339))
		fmt.Printf("URI:       %s\n", uri)
		fmt.Println()
	}
}
