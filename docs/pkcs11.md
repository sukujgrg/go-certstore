# PKCS#11 Usage

This document covers practical PKCS#11 usage with `go-certstore`, including
YubiKey/OpenSC-style hardware tokens and SoftHSM for local development.

## Overview

Use the PKCS#11 backend when your client certificate identity lives in a token
or provider that exposes a PKCS#11 module.

Typical examples:

- YubiKey PIV via OpenSC
- smart cards
- HSMs
- SoftHSM for local testing

The backend requires an explicit PKCS#11 module path:

```go
store, err := certstore.Open(
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module("/path/to/pkcs11/module"),
)
```

## YubiKey / OpenSC

For YubiKey PIV on systems using OpenSC, the PKCS#11 module is typically
`opensc-pkcs11.so`.

Example:

```go
store, err := certstore.Open(
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module("/usr/local/lib/opensc-pkcs11.so"),
    certstore.WithPKCS11TokenLabel("YubiKey PIV"),
    certstore.WithPKCS11PINPrompt(func(info certstore.PromptInfo) (string, error) {
        return os.Getenv("YUBIKEY_PIN"), nil
    }),
)
if err != nil {
    return err
}
defer store.Close()

ident, err := certstore.FindIdentity(store, certstore.FindIdentityOptions{
    Backend:               certstore.BackendPKCS11,
    ValidOnly:             true,
    RequireHardwareBacked: true,
    PreferHardwareBacked:  true,
})
if err != nil {
    return err
}
defer ident.Close()
```

The library intentionally leaves PIN collection to the application. Use
`WithPKCS11PINPrompt(...)` to plug in whatever is appropriate for your app:

- GUI prompt
- terminal prompt
- keychain/secret manager lookup
- env/config injection

Selection note:

- `FindIdentity` returns one best-ranked identity when multiple PKCS#11
  identities match
- `FindIdentities` returns all matching identities
- `FindTLSCertificate` returns one best-ranked TLS certificate

## Explicit signer cleanup

Some backends keep native key handles alive while the signer exists. When you
obtain a signer directly, close it explicitly when you are done:

```go
signer, err := ident.Signer()
if err != nil {
    return err
}
defer certstore.CloseSigner(signer)
```

This is most relevant for PKCS#11 and other native-handle-backed signers.

## SoftHSM setup

SoftHSM is useful for local development and CI because it behaves like a
software token and supports PKCS#11.

End-to-end, the setup flow is:

1. Install SoftHSM.
2. Create a token directory and `softhsm2.conf`.
3. Initialize a token with a user PIN.
4. Generate or convert a private key to PKCS#8 PEM.
5. Import the private key into the token.
6. Import the leaf certificate and any CA certificates.
7. Open the token from Go with `BackendPKCS11`.

### Install SoftHSM

macOS (Homebrew):

```sh
brew install softhsm
```

Typical Homebrew paths:

```sh
export SOFTHSM2_UTIL=/opt/homebrew/Cellar/softhsm/2.7.0/bin/softhsm2-util
export SOFTHSM2_MODULE=/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so
```

Linux:

```sh
sudo apt install softhsm2
```

Typical Linux paths:

```sh
export SOFTHSM2_UTIL=/usr/bin/softhsm2-util
export SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
```

### Create a token directory and config

```sh
mkdir -p /tmp/softhsm-tokens
cat > /tmp/softhsm2.conf <<'EOF'
directories.tokendir = /tmp/softhsm-tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF

export SOFTHSM2_CONF=/tmp/softhsm2.conf
```

### Initialize a token

This creates a new token in the configured token directory. The example below
uses:

- token label: `go-certstore-test`
- security officer PIN: `654321`
- user PIN: `123456`

The user PIN is the PIN your Go code will supply through
`WithPKCS11PINPrompt(...)`.

```sh
"$SOFTHSM2_UTIL" --module "$SOFTHSM2_MODULE" \
  --init-token --free \
  --label "go-certstore-test" \
  --so-pin 654321 \
  --pin 123456
```

You can confirm that the token exists with:

```sh
"$SOFTHSM2_UTIL" --module "$SOFTHSM2_MODULE" --show-slots
```

### Prepare a private key and certificate

If you already have a PKCS#8 PEM private key and matching certificate, you can
skip this section.

Generate a test RSA key and self-signed certificate with OpenSSL:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem

openssl req -new -x509 \
  -key key.pem \
  -out client-cert.pem \
  -days 365 \
  -subj "/CN=pkcs11-client.example.com"
```

If your key is not already PKCS#8 PEM, convert it first:

```sh
openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem
mv key-pkcs8.pem key.pem
```

### Import a PKCS#8 private key and certificates

The private key file must be PKCS#8 PEM.

```sh
"$SOFTHSM2_UTIL" --module "$SOFTHSM2_MODULE" \
  --import key.pem \
  --token "go-certstore-test" \
  --label "client-key" \
  --id 01 \
  --pin 123456

"$SOFTHSM2_UTIL" --module "$SOFTHSM2_MODULE" \
  --import client-cert.pem \
  --import-type cert \
  --token "go-certstore-test" \
  --label "client-key" \
  --id 01 \
  --pin 123456

"$SOFTHSM2_UTIL" --module "$SOFTHSM2_MODULE" \
  --import ca-cert.pem \
  --import-type cert \
  --token "go-certstore-test" \
  --label "client-ca" \
  --id ca \
  --pin 123456
```

At this point you have:

- a private key stored in the token
- a leaf certificate associated with that key
- an optional CA certificate available for chain building

### Open the token from Go

```go
store, err := certstore.Open(
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module(os.Getenv("SOFTHSM2_MODULE")),
    certstore.WithPKCS11TokenLabel("go-certstore-test"),
    certstore.WithPKCS11PINPrompt(func(info certstore.PromptInfo) (string, error) {
        return os.Getenv("PKCS11_PIN"), nil
    }),
)
if err != nil {
    return err
}
defer store.Close()
```

The repository also contains a full runnable integration test:

- [pkcs11_integration_test.go](/Users/suku/github/sukujgrg/go-certstore/pkcs11_integration_test.go)

## TLS helper flow

For TLS client authentication, prefer the helper:

```go
tlsConfig := &tls.Config{
    GetClientCertificate: certstore.GetClientCertificateFunc(
        []certstore.Option{
            certstore.WithBackend(certstore.BackendPKCS11),
            certstore.WithPKCS11Module(os.Getenv("SOFTHSM2_MODULE")),
            certstore.WithPKCS11TokenLabel("go-certstore-test"),
            certstore.WithPKCS11PINPrompt(func(info certstore.PromptInfo) (string, error) {
                return os.Getenv("PKCS11_PIN"), nil
            }),
        },
        certstore.SelectOptions{
            RequireClientAuthEKU: true,
            PreferHardwareBacked: true,
        },
    ),
}
```
