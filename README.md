# go-certstore

A Go library for accessing the system certificate store for client certificate authentication (mTLS). It provides a read-only, interface-driven API for enumerating identities and signing with their private keys.

## Platform support

| Platform | Backend | CGo required |
|----------|---------|:------------:|
| macOS    | Keychain (Security.framework) | Yes |
| Windows  | CertStore (CNG / CryptoAPI)   | Yes |
| Linux    | — (returns error)             | No  |

## Install

```
go get github.com/sukujgrg/go-certstore@latest
```

## API

```go
// Open the system certificate store.
func Open() (Store, error)

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

// FilterIdentities opens the store and returns identities matching the filter.
func FilterIdentities(filter FilterFunc) ([]Identity, error)

type FilterFunc func(*x509.Certificate) bool
```

## Usage

Use `getCertificate` as your `tls.Config.GetClientCertificate` callback. Filtering by CN, issuer, expiry, etc. is done by the caller — the library just enumerates what's in the store.

```go
func getCertificate(cn, issuer string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
    return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
        store, err := certstore.Open()
        if err != nil {
            return nil, err
        }
        defer store.Close()

        idents, err := store.Identities()
        if err != nil {
            return nil, err
        }

        for _, ident := range idents {
            defer ident.Close()

            cert, err := ident.Certificate()
            if err != nil {
                continue
            }
            if cert.Subject.CommonName != cn {
                continue
            }
            if time.Now().After(cert.NotAfter) {
                continue
            }
            if cert.Issuer.CommonName != issuer {
                continue
            }

            signer, err := ident.Signer()
            if err != nil {
                return nil, err
            }
            return &tls.Certificate{
                Certificate: [][]byte{cert.Raw},
                PrivateKey:  signer,
            }, nil
        }
        return nil, fmt.Errorf("no valid certificate found for CN=%s, Issuer=%s", cn, issuer)
    }
}
```

## Runnable examples

The `_examples/` directory contains standalone programs that demonstrate the library.

### List certificates

```sh
cd _examples/list

# list all certificates
go run .

# filter by subject CN (substring match)
go run . -cn myhost

# filter by issuer CN, only valid (unexpired), and verify private key access
go run . -issuer "My CA" -valid -check-key
```

### mTLS check

Check if a specific mTLS client certificate is available and usable:

```sh
cd _examples/mtls-check

go run . -cn myhost.example.com -issuer "My Issuing CA"
```

Example output:

```
Looking for: CN=myhost.example.com, Issuer=My Issuing CA

Subject:  CN=myhost.example.com
Issuer:   CN=My Issuing CA
Serial:   1a2b3c4d
Validity: 2025-01-15 to 2026-01-15
Status:   VALID
Expires:  301 days remaining
Key:      OK

mTLS is ready.
```

## Signing support

| Algorithm | macOS | Windows (CNG) | Windows (CryptoAPI) |
|-----------|:-----:|:--------------:|:-------------------:|
| RSA PKCS#1 v1.5 (SHA1/256/384/512) | Yes | Yes | Yes |
| RSA-PSS (SHA256/384/512) | Yes | Yes | — |
| ECDSA (SHA1/256/384/512) | Yes | Yes | — |

## Credits

- macOS implementation inspired by [getvictor/mtls](https://github.com/getvictor/mtls)
- Interface design and Windows implementation based on [smimesign/certstore](https://github.com/github/smimesign)

## License

MIT
