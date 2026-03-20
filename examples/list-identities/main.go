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
		backend = flag.String("backend", "auto", "backend: auto or pkcs11")
		module  = flag.String("module", "", "PKCS#11 module path")
		token   = flag.String("token", "", "PKCS#11 token label")
		pin     = flag.String("pin", "", "PKCS#11 user PIN")
		valid   = flag.Bool("valid", false, "only show currently valid identities")
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
		ValidOnly: *valid,
	}
	if *backend == "pkcs11" {
		findOpts.Backend = certstore.BackendPKCS11
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
