# PKCS#11 Usage

This document describes PKCS#11 usage with `go-certstore`. It covers YubiKey
and OpenSC hardware tokens, and SoftHSM for local development.

## Understand the PKCS#11 backend

Use the PKCS#11 backend when the client certificate identity lives in a token
or provider that exposes a PKCS#11 module.

Examples:

- YubiKey PIV through OpenSC
- smart cards
- hardware security modules (HSMs)
- SoftHSM for local testing

The backend requires an explicit PKCS#11 module path:

```go
ctx := context.Background()
store, err := certstore.Open(ctx,
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module("/path/to/pkcs11/module"),
)
if err != nil {
    return err
}
defer store.Close()
```

## Use YubiKey or OpenSC

For YubiKey PIV on systems that use OpenSC, the PKCS#11 module is usually
`opensc-pkcs11.so`.

Example:

```go
ctx := context.Background()
store, err := certstore.Open(ctx,
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module("/usr/local/lib/opensc-pkcs11.so"),
    certstore.WithPKCS11TokenLabel("YubiKey PIV"),
    certstore.WithCredentialPrompt(func(info certstore.PromptInfo) ([]byte, error) {
        return []byte(os.Getenv("YUBIKEY_PIN")), nil
    }),
)
if err != nil {
    return err
}
defer store.Close()

ident, err := certstore.FindIdentity(ctx, store, certstore.FindIdentityOptions{
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

The library does not collect PINs. The application supplies credentials through
`WithCredentialPrompt(...)`. Suitable sources include:

- a GUI prompt
- a terminal prompt
- a keychain or secret manager
- an environment variable or configuration value

The callback returns `[]byte`, not a `string`. The library clears that buffer
after use. The library also clears the buffer if the callback returns an error.
If secret lifetime is important, return a dedicated buffer. Do not return a
shared slice that other code will use again.

For PKCS#11 login, the package passes a temporary string view to the
dependency. The cgo runtime or the dependency can make an internal copy. This
method is not a high-assurance secret-memory system.

Selection behavior:

- `FindIdentity` returns one best-ranked identity when more than one PKCS#11 identity matches
- `FindIdentities` returns all matching identities
- `FindTLSCertificate` returns one best-ranked TLS certificate

## Close signers explicitly

Some backends keep native key handles alive while the signer exists. When you
get a signer directly, close it when you are done:

```go
signer, err := ident.Signer(ctx)
if err != nil {
    return err
}
defer certstore.CloseSigner(signer)
```

This is most important for PKCS#11 and other signers that use native handles.

`crypto.Signer.Sign` does not accept a context. PKCS#11 signers can reuse the
context from `Identity.Signer(ctx)` if the token requires a later login during
signing. Prefer a long-lived context unless that later sign path must stop
after cancellation.

## Set up SoftHSM

SoftHSM is useful for local development and CI. It behaves like a software
token and supports PKCS#11.

Setup steps:

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

Homebrew paths:

```sh
export SOFTHSM2_UTIL="$(brew --prefix softhsm)/bin/softhsm2-util"
export SOFTHSM2_MODULE="$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so"
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

This command creates a new token in the configured token directory. The example
uses:

- token label: `go-certstore-test`
- security officer PIN: `654321`
- user PIN: `123456`

Your Go code supplies the user PIN through `WithCredentialPrompt(...)`.

```sh
"$SOFTHSM2_UTIL" --module "$SOFTHSM2_MODULE" \
  --init-token --free \
  --label "go-certstore-test" \
  --so-pin 654321 \
  --pin 123456
```

Confirm that the token exists:

```sh
"$SOFTHSM2_UTIL" --module "$SOFTHSM2_MODULE" --show-slots
```

### Prepare a private key and certificate

If you already have a PKCS#8 PEM private key and a matching certificate, skip
this section.

Generate a test RSA key and a self-signed certificate with OpenSSL:

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

For the self-signed leaf from the previous section, import only the key and the
leaf certificate:

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
```

If you have a CA-signed leaf and a CA certificate, import the CA as well:

```sh
"$SOFTHSM2_UTIL" --module "$SOFTHSM2_MODULE" \
  --import ca-cert.pem \
  --import-type cert \
  --token "go-certstore-test" \
  --label "client-ca" \
  --id ca \
  --pin 123456
```

Skip the CA import for the self-signed leaf in this guide. That leaf is not
signed by a separate CA.

At this point you have:

- a private key in the token
- a leaf certificate associated with that key
- an optional CA certificate for chain building, if you imported one

### Open the token from Go

```go
ctx := context.Background()
store, err := certstore.Open(ctx,
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module(os.Getenv("SOFTHSM2_MODULE")),
    certstore.WithPKCS11TokenLabel("go-certstore-test"),
    certstore.WithCredentialPrompt(func(info certstore.PromptInfo) ([]byte, error) {
        return []byte(os.Getenv("PKCS11_PIN")), nil
    }),
)
if err != nil {
    return err
}
defer store.Close()
```

The repository also contains a full runnable integration test:

- [pkcs11_integration_test.go](../pkcs11_integration_test.go)

Runnable SoftHSM examples:

```sh
export PKCS11_PIN=123456

go run ./examples/list-identities \
  -backend pkcs11 \
  -module "$SOFTHSM2_MODULE" \
  -token "go-certstore-test"

go run ./examples/mtls-source \
  -backend pkcs11 \
  -module "$SOFTHSM2_MODULE" \
  -token "go-certstore-test" \
  -subject "pkcs11-client.example.com"
```

See [examples.md](examples.md) for `tls-client` and `export-cert`.

## Configure a TLS client certificate

For TLS client authentication, open the store one time and use
`NewClientCertificateSource`. Handshakes then reuse cached certificates and
signers:

```go
store, err := certstore.Open(ctx,
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module(os.Getenv("SOFTHSM2_MODULE")),
    certstore.WithPKCS11TokenLabel("go-certstore-test"),
    certstore.WithCredentialPrompt(func(info certstore.PromptInfo) ([]byte, error) {
        return []byte(os.Getenv("PKCS11_PIN")), nil
    }),
)
if err != nil {
    return err
}
defer store.Close()

source := certstore.NewClientCertificateSource(ctx, store, certstore.SelectOptions{
    RequireClientAuthEKU: true,
    PreferHardwareBacked: true,
})
defer source.Close()

tlsConfig := &tls.Config{
    GetClientCertificate: source.GetClientCertificate,
}
```

Prefer this method over `GetClientCertificateFunc`. That helper opens the
PKCS#11 module for each handshake. It can leave token sessions waiting for
garbage collection.

The source caches returned certificates across handshakes. It skips expired
cache entries when it selects again. It keeps previously returned signers alive
until `Close` for handshakes that are still in progress.

The source does not monitor the token for replaced identities. Recreate the
source when the application must load a new certificate. As an alternative,
keep the process lifetime aligned with the certificate lifetime.

The source reuses the context from construction. The Go TLS handshake API does
not pass a context for each handshake into `tls.Config.GetClientCertificate`.
