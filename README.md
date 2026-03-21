# go-certstore

A Go library for accessing client certificate identities across native OS stores and token-backed backends.

Currently supported:

- macOS Keychain
- Windows Cert Store
- explicit-module PKCS#11 tokens

## Platform support

| Platform | Backend | Status | CGo required |
|----------|---------|--------|:------------:|
| macOS    | Keychain (Security.framework) | Implemented | Yes |
| Windows  | CertStore (CNG / CryptoAPI)   | Implemented | Yes |
| Linux    | Native system store           | Not supported | No |
| Any      | PKCS#11 (explicit module path) | Implemented | Yes |
| Any      | NSS / p11-kit discovery       | Not implemented yet | TBD |

## Install

```sh
go get github.com/sukujgrg/go-certstore@latest
```

## Core API

```go
func Open(opts ...Option) (Store, error)

type Store interface {
    Identities() ([]Identity, error)
    Close()
}

type Identity interface {
    Certificate() (*x509.Certificate, error)
    CertificateChain() ([]*x509.Certificate, error)
    Signer() (crypto.Signer, error)
    Close()
}
```

Important helpers:

- `FindIdentity` / `FindIdentities`
- `FindTLSCertificate`
- `GetClientCertificateFunc`
- `CloseSigner`

## Quick start

Default backend for the current platform:

```go
store, err := certstore.Open()
```

Explicit PKCS#11 backend:

```go
store, err := certstore.Open(
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module("/path/to/pkcs11/module"),
    certstore.WithPKCS11TokenLabel("YubiKey PIV"),
    certstore.WithPKCS11PINPrompt(func(info certstore.PromptInfo) (string, error) {
        return os.Getenv("PKCS11_PIN"), nil
    }),
)
```

TLS client certificate helper:

```go
tlsConfig := &tls.Config{
    GetClientCertificate: certstore.GetClientCertificateFunc(nil, certstore.SelectOptions{
        SubjectCN:            "myhost.example.com",
        IssuerCN:             "My Issuing CA",
        RequireClientAuthEKU: true,
    }),
}
```

## Docs

- [PKCS#11 Usage](/Users/suku/github/sukujgrg/go-certstore/docs/pkcs11.md)
- [Examples](/Users/suku/github/sukujgrg/go-certstore/docs/examples.md)

The PKCS#11 guide includes:

- YubiKey / OpenSC usage
- application-provided PIN callback
- explicit signer cleanup
- SoftHSM installation
- how to create a SoftHSM config and token
- how to import PKCS#8 keys and certificates
- TLS helper usage with tokens

## Runnable examples

Runnable programs now live under `examples/`.

- [examples/list-identities](/Users/suku/github/sukujgrg/go-certstore/examples/list-identities/main.go)
- [examples/tls-client](/Users/suku/github/sukujgrg/go-certstore/examples/tls-client/main.go)

Run them with:

```sh
go run ./examples/list-identities
go run ./examples/tls-client -subject "client.example.com"
```

See [docs/examples.md](/Users/suku/github/sukujgrg/go-certstore/docs/examples.md) for PKCS#11 flag examples.

## Signing support

| Algorithm | macOS | Windows (CNG) | Windows (CryptoAPI) | PKCS#11 |
|-----------|:-----:|:--------------:|:-------------------:|:-------:|
| RSA PKCS#1 v1.5 (SHA1/256/384/512) | Yes | Yes | Yes | Yes |
| RSA-PSS (SHA256/384/512) | Yes | Yes | — | Yes |
| ECDSA (SHA1/256/384/512) | Yes | Yes | — | Yes |

## Notes

- PKCS#11 support currently requires an explicit module path.
- NSS and `p11-kit` discovery are intentionally not implemented yet.
- PKCS#11 identities now expose richer metadata through `PKCS11IdentityInfo`.
- Native-handle-backed signers can be cleaned up explicitly with `CloseSigner`.

## Credits

- macOS implementation inspired by [getvictor/mtls](https://github.com/getvictor/mtls)

## License

MIT
