# go-certstore

`go-certstore` gives Go applications access to X.509 certificate identities.
It supports native operating-system stores, PKCS#11 tokens, and NSS databases.

An identity contains a certificate and its private-key signer. The private key
stays in its native store, token, or database.

## Platform support

| Backend | Host operating system | Status | Requires cgo |
|---|---|---|:---:|
| Keychain (`Security.framework`) | macOS | Supported | Yes |
| Certificate Store (CNG or CryptoAPI) | Windows | Supported | Yes |
| Native system store | Linux | Not supported | No |
| PKCS#11 with an explicit module path | All supported platforms | Supported | Yes |
| NSS with an explicit `softokn3` module path and profile directory | All supported platforms | Supported | Yes |

PKCS#11 supports hardware and software tokens. Examples include YubiKey PIV,
OpenSC smart cards, hardware security modules (HSMs), and SoftHSM.

The application must supply the module path and all required credentials.

## Install the library

```sh
go get github.com/sukujgrg/go-certstore@latest
```

## Start quickly

Open the default backend for the current platform:

```go
ctx := context.Background()
store, err := certstore.Open(ctx)
if err != nil {
    return err
}
defer store.Close()
```

Linux does not have a native backend. On Linux, select `BackendPKCS11` or
`BackendNSS` explicitly.

### Open a PKCS#11 backend

```go
ctx := context.Background()
store, err := certstore.Open(ctx,
    certstore.WithBackend(certstore.BackendPKCS11),
    certstore.WithPKCS11Module("/path/to/pkcs11/module"),
    certstore.WithPKCS11TokenLabel("YubiKey PIV"),
    certstore.WithCredentialPrompt(func(info certstore.PromptInfo) ([]byte, error) {
        return []byte(os.Getenv("PKCS11_PIN")), nil
    }),
)
if err != nil {
    return err
}
defer store.Close()
```

### Open an NSS backend

```go
ctx := context.Background()
store, err := certstore.Open(ctx,
    certstore.WithBackend(certstore.BackendNSS),
    certstore.WithNSSModule("/path/to/libsoftokn3.so"),
    certstore.WithNSSProfileDir("/path/to/nssdb"),
    certstore.WithCredentialPrompt(func(info certstore.PromptInfo) ([]byte, error) {
        return []byte(os.Getenv("CERTSTORE_PIN")), nil
    }),
)
if err != nil {
    return err
}
defer store.Close()
```

### Select a Windows store

The Windows backend uses `CurrentUser\\MY` by default. Use options to select a
different store:

```go
ctx := context.Background()
store, err := certstore.Open(ctx,
    certstore.WithBackend(certstore.BackendWindows),
    certstore.WithWindowsStoreLocation(certstore.WindowsStoreLocalMachine),
    certstore.WithWindowsStoreName("MY"),
)
if err != nil {
    return err
}
defer store.Close()
```

Read-only access to a `LocalMachine` store does not require elevated
permissions in all cases. The private key access control list (ACL) controls
access to each private key. Creating or changing items in a `LocalMachine`
store usually requires elevated permissions.

### Configure a TLS client certificate

Use a long-lived store with `NewClientCertificateSource`:

```go
ctx := context.Background()
store, err := certstore.Open(ctx)
if err != nil {
    return err
}
defer store.Close()

source := certstore.NewClientCertificateSource(ctx, store, certstore.SelectOptions{
    SubjectCN:            "myhost.example.com",
    IssuerCN:             "My Issuing CA",
    RequireClientAuthEKU: true,
})
defer source.Close()

tlsConfig := &tls.Config{
    GetClientCertificate: source.GetClientCertificate,
}
```

The source caches compatible certificates and signers between TLS handshakes.
It keeps each returned certificate and signer alive until `Close`, so
concurrent handshakes are safe. Call `Close` to release token sessions.

Use this method for PKCS#11 and NSS. `GetClientCertificateFunc` opens the store
for each handshake. That cost is usually acceptable for native stores. Prefer
`NewClientCertificateSource` or `ClientCertificateFunc` for token backends.

## Use the core API

```go
func Open(ctx context.Context, opts ...Option) (Store, error)

type Store interface {
    Identities(ctx context.Context) ([]Identity, error)
    Close()
}

type Identity interface {
    Certificate(ctx context.Context) (*x509.Certificate, error)
    CertificateChain(ctx context.Context) ([]*x509.Certificate, error)
    Signer(ctx context.Context) (crypto.Signer, error)
    Close()
}
```

The package also provides these helpers:

- `FindIdentity` returns the best matching identity.
- `FindIdentities` returns all matching identities.
- `FilterIdentities` applies custom certificate filter functions.
- `FindTLSCertificate` returns the best matching TLS client certificate.
- `NewClientCertificateSource` creates a closeable TLS certificate source.
- `ClientCertificateFunc` creates a TLS callback for an open store.
- `GetClientCertificateFunc` creates a TLS callback that opens the store for each handshake.
- `CloseSigner` releases resources held by a signer.

Close a signer that you get directly from `Identity.Signer`:

```go
signer, err := ident.Signer(ctx)
if err != nil {
    return err
}
defer certstore.CloseSigner(signer)
```

This operation releases native handles and token sessions promptly when the
backend supports explicit cleanup. It does not wait for garbage collection.

## Close resources

`Store.Close`, `Identity.Close`, and closeable signer `Close` methods are safe
to call more than one time. You can call them while other methods run.

An operation returns `ErrClosed` if resource release completes first. Cached
certificate data and fixed identity metadata can remain available after a close
operation.

Close each client certificate source, signer, and identity that you own. Then,
close the store.

## Use contexts

All public APIs that accept `context.Context` require a non-nil context. Use
`context.Background()` if you do not need cancellation or a deadline.

TLS callbacks do not supply a context for each handshake. These functions reuse
the context that you supply when you create the callback:

- `NewClientCertificateSource`
- `ClientCertificateFunc`
- `GetClientCertificateFunc`

Token-backed signers can also keep the context from `Identity.Signer` for later
re-authentication. The `crypto.Signer.Sign` method does not accept a context.

Use a long-lived context in both cases. Use a short-lived context only if later
token access must stop after cancellation.

`ClientCertificateSource` does not monitor the store for replacement
identities. Recreate the source when the application must load a new
certificate. As an alternative, keep the process lifetime aligned with the
certificate lifetime.

## Select identities

Helpers that select one identity return the best match. They do not return all
matches.

When more than one identity matches, the current ranking uses these scoring
preferences:

1. If requested, put identities that are known to use hardware above other
   matches.
2. Give a smaller score increase to certificates that are currently valid.
3. Prefer a certificate with a later expiration time.

The score is an approximate ranking. It does not give a strict sort order.

Set `SelectOptions.RequireCurrentlyValid` to reject expired and not-yet-valid
certificates. Without that option, validity only changes the ranking score.
`ClientCertificateSource` always requires a currently valid certificate.

Use `FindIdentities` or `FilterIdentities` to inspect all matches.

## Use identity metadata

Metadata content depends on the backend:

- Native backends supply the backend name, key type, label, and a certificate-derived URI.
- PKCS#11 supplies token data through `PKCS11IdentityInfo`.
- NSS supplies backend data through `NSSIdentityInfo`.

Capability metadata has two interfaces:

- `IdentityInfo` supplies Boolean values such as `IsHardwareBacked()`.
- `IdentityCapabilityInfo` supplies `yes`, `no`, or `unknown` states.

Use `IdentityCapabilityInfo` if the application must distinguish `no` from
`unknown`.

## Handle credentials

`WithCredentialPrompt` returns credentials as `[]byte`, not as `string`.

- Return a dedicated buffer if secret lifetime is important.
- Do not return a shared slice that other code will use again.
- The library clears the returned buffer after use.
- The library also clears the buffer if the callback returns an error.

For PKCS#11 and NSS login, the package passes a temporary string view to the
dependency. The cgo runtime or the dependency can make an internal copy. This
method is not a high-assurance secret-memory system.

## Check signing support

| Algorithm | macOS | Windows CNG | Windows CryptoAPI | PKCS#11 | NSS |
|---|:---:|:---:|:---:|:---:|:---:|
| RSA PKCS#1 v1.5 with SHA-1, SHA-256, SHA-384, or SHA-512 | Yes | Yes | Yes | Yes | Yes |
| RSA-PSS with SHA-256, SHA-384, or SHA-512 | Yes | Yes | No | Yes | Yes |
| ECDSA with SHA-1, SHA-256, SHA-384, or SHA-512 | Yes | Yes | No | Yes | Yes |

Direct use of `crypto.Signer` can have backend-specific limits. On macOS,
RSA-PSS requires a salt length that equals the hash length.

## Handle errors

Use `errors.Is` to test exported errors:

- `ErrIdentityNotFound` means that no identity matches the filters.
- `ErrCredentialRequired` means that the backend requires credentials, or that
  the credential state has a problem.
- `ErrIncorrectCredential` means that the backend rejected the credentials.
- `ErrUnsupportedBackend` means that the backend is not available on the
  current platform, or that the backend is not implemented.
- `ErrInvalidConfiguration` means that an option or context is not valid.
- `ErrClosed` means that code used a resource after it closed.

## Understand backend selection

`Open(context.Background())` uses the native backend for the current platform.
On Linux, it returns `ErrUnsupportedBackend`. Linux has no single standard
system store for client certificates that this library can target.

`Open(context.Background(), WithBackend(BackendAuto), ...)` uses these rules:

- macOS and Windows use the native backend by default.
- A PKCS#11 option selects PKCS#11 and requires a module path.
- An NSS option selects NSS and requires a module path and profile directory.
- A Windows store option selects the configured Windows system store.
- Do not use Windows store options with PKCS#11 or NSS options.

## Understand the project scope

Use this library to:

- List certificate and private-key identities.
- Select identities for mutual TLS (mTLS) and other client-certificate operations.
- Get a leaf certificate or an available X.509 certificate chain.
- Get a `crypto.Signer` that uses the key in its original backend.

Do not use this library to:

- Manage SSH keys or SSH certificates.
- Manage general keys or secrets.
- Create identities or certificates.
- Hide backend configuration from the application.

The library accesses backends, lists identities, creates signers, and supplies
TLS helpers. The application has these responsibilities:

- Find modules, profiles, and tokens.
- Select the backend for each environment.
- Get credentials from users.
- Select defaults and supply the user interface.
- Supply other environment-specific behavior.

For this reason, PKCS#11 and NSS require explicit module and profile options.

## Migrate from v0.1.4 or earlier

Version 0.2.0 introduced two breaking changes.

### Pass an open store to `FilterIdentities`

`FilterIdentities` no longer opens the default store. Open the required store,
pass it to `FilterIdentities`, and close it after use.

In v0.1.4 and earlier versions:

```go
idents, err := certstore.FilterIdentities(ctx, filter)
```

Current API:

```go
store, err := certstore.Open(ctx, openOpts...)
if err != nil {
    return err
}
defer store.Close()

idents, err := certstore.FilterIdentities(ctx, store, filter)
```

Close each returned identity. The explicit store lets the application select
PKCS#11, NSS, or a specific Windows store.

### Do not pass a nil context

In v0.1.4 and earlier versions, public APIs used `context.Background()` when
the context was nil. These APIs now return `ErrInvalidConfiguration`.

In v0.1.4 and earlier versions:

```go
store, err := certstore.Open(nil)
```

Current API:

```go
ctx := context.Background()
store, err := certstore.Open(ctx)
```

This rule applies to all APIs that accept a context.

## Read more

- [PKCS#11 usage](docs/pkcs11.md)
- [NSS usage](docs/nss.md)
- [Examples](docs/examples.md)

Runnable programs are in the [`examples`](examples/) directory. These programs
do not start a live TLS handshake or connect to a remote server.

Use `examples/mtls-source` as a model for long-lived `tls.Config` setup. Then,
use the configuration with `tls.Dial` or `http.Transport`.

## Run local checks

- Run `make check` to test the library on the current host.
- Run `make lint` to run `golangci-lint`.
- Run `make check-macos` to test the library and the macOS native backend.
- Run `make check-linux` to run the Linux checks in Docker.

On Linux, use `make check` unless you require the Docker environment that CI
uses.

CI runs lint on Ubuntu. It also runs race tests on Linux. CI builds the examples
and runs platform tests on Linux, macOS, and Windows.

## Credits

The macOS implementation uses ideas from
[`getvictor/mtls`](https://github.com/getvictor/mtls).

## License

MIT

## Documentation style

This README aims to follow ASD-STE100 Simplified Technical English. Keep future
edits consistent with its principles: use short sentences, active voice, and
one term for each meaning.
