# go-certstore

A Go library for accessing X.509 certificate identities across native OS stores and token/database-backed backends.

## Platform support

| Backend | Host OS | Status | CGo required |
|---------|---------|--------|:------------:|
| Keychain (Security.framework) | macOS | Implemented | Yes |
| CertStore (CNG / CryptoAPI) | Windows | Implemented | Yes |
| Native system store | Linux | Not supported | No |
| PKCS#11 (explicit module path) | Cross-platform | Implemented | Yes |
| NSS (explicit softokn3 module path + profile dir) | Cross-platform | Implemented | Yes |

PKCS#11 support includes hardware and software tokens such as YubiKey PIV via
OpenSC, smart cards, HSMs, and SoftHSM, as long as the application provides an
explicit module path and any required credentials.

## Install

```sh
go get github.com/sukujgrg/go-certstore@latest
```

## Migrating from ≤ v0.1.4

Two breaking changes affect callers upgrading from v0.1.4 or earlier.

### FilterIdentities requires an open store

`FilterIdentities` no longer opens the platform-default store internally. The
application must open the desired backend, pass that `Store` to
`FilterIdentities`, and close the store when finished.

Before (≤ v0.1.4):

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

Returned identities remain caller-owned and must also be closed. Making the
store explicit allows callers to select PKCS#11, NSS, or a specific Windows
store instead of being limited to the platform default.

### Nil contexts are rejected

In ≤ v0.1.4, public APIs that accept `context.Context` treated `nil` as
`context.Background()`. They now return `ErrInvalidConfiguration` when `ctx`
is nil.

Before (≤ v0.1.4):

```go
store, err := certstore.Open(nil)
```

Current API:

```go
ctx := context.Background()
store, err := certstore.Open(ctx)
```

Pass `context.Background()` when you do not need cancellation or deadlines.
This applies to all context-taking entry points, including `Open`,
`FilterIdentities`, `FindIdentity`, `FindIdentities`, `FindTLSCertificate`,
and TLS client-certificate helpers.

## Quick start

Default backend for the current platform:

```go
ctx := context.Background()
store, err := certstore.Open(ctx)
if err != nil {
    return err
}
defer store.Close()
```

On Linux, the native backend is intentionally unsupported, so callers should
choose `BackendPKCS11` or `BackendNSS` explicitly instead of relying on the
platform default.

Explicit PKCS#11 backend:

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

Explicit NSS backend:

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

Windows store selection (defaults to CurrentUser\\MY):

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

TLS client certificate helper:

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

Prefer `NewClientCertificateSource` (or `ClientCertificateFunc`) with a
long-lived store for PKCS#11 and NSS. The source caches returned
certificates/signers across handshakes (keeping previously returned ones alive
until `Close`, so concurrent handshakes are safe) and `Close` releases those
token sessions deterministically. `GetClientCertificateFunc` is still available
when reopening the store on each handshake is acceptable (typically native
macOS/Windows stores).

## Signing support

| Algorithm | macOS | Windows (CNG) | Windows (CryptoAPI) | PKCS#11 | NSS |
|-----------|:-----:|:--------------:|:-------------------:|:-------:|:---:|
| RSA PKCS#1 v1.5 (SHA1/256/384/512) | Yes | Yes | Yes | Yes | Yes |
| RSA-PSS (SHA256/384/512) | Yes | Yes | — | Yes | Yes |
| ECDSA (SHA1/256/384/512) | Yes | Yes | — | Yes | Yes |

Direct `crypto.Signer` use can still have backend-specific limits. In
particular, the macOS backend supports RSA-PSS only when the requested salt
length equals the hash length, matching the Security.framework algorithms used
here.

## Core API

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

`Store.Close`, `Identity.Close`, and closeable signer `Close` methods are
idempotent and safe to call concurrently with their other methods. Operations
that lose a race with resource release return `ErrClosed`; cached certificate
data and immutable identity metadata may remain available after close.

Important helpers:

- `FindIdentity` / `FindIdentities`
- `FilterIdentities` for arbitrary certificate predicates
- `FindTLSCertificate`
- `NewClientCertificateSource` / `ClientCertificateFunc`
- `GetClientCertificateFunc`
- `CloseSigner`

Use `CloseSigner` when you obtain a signer directly from `Identity.Signer(ctx)`:

```go
signer, err := ident.Signer(ctx)
if err != nil {
    return err
}
defer certstore.CloseSigner(signer)
```

That lets backends release native handles or token sessions promptly instead of
waiting for garbage collection.

## Context Semantics

All public APIs that accept `context.Context` require a non-nil context. Use
`context.Background()` when cancellation is not needed.

Two lifecycle details matter in practice:

- `NewClientCertificateSource`, `ClientCertificateFunc`, and
  `GetClientCertificateFunc` reuse the context you pass when the callback is
  created, because Go's TLS callback does not provide a per-handshake context
- token-backed signers may retain the context passed to `Identity.Signer(ctx)`
  for later re-authentication, because `crypto.Signer.Sign` does not accept a
  context

For both cases, prefer a long-lived context unless you explicitly want
cancellation to stop later token access.

For PKCS#11 and NSS, prefer `NewClientCertificateSource` with a store you keep
open for the life of the TLS client or server. The source reuses compatible,
currently valid cached certificates/signers across handshakes and keeps
previously returned ones alive until `Close` so concurrent handshakes stay safe;
call `Close` to release those token sessions when finished. It does not watch
the store for replaced identities—recreate the source, or keep process lifetime
aligned with certificate lifetime, when rotation must be picked up.
`GetClientCertificateFunc` reopens the store on every handshake, which is
usually fine for native stores but costly for token backends.

## Credential Handling

`WithCredentialPrompt` returns credentials as `[]byte`, not `string`.

- the library wipes the returned buffer after use, including when the
  callback itself returns an error
- callers that care about secret lifetime should return a dedicated buffer, not
  a shared slice they plan to reuse
- for PKCS#11/NSS login, this package now passes a transient string view of
  that buffer to the underlying dependency instead of allocating an extra Go
  copy itself, but cgo and the dependency may still copy internally
- this improves handling but is not a high-assurance secret-memory scheme

## Scope

`go-certstore` is a library for working with X.509 certificate identities that
already exist in native stores or token/database backends.

It is intended for:

- enumerating certificate + private key identities
- selecting identities for mTLS and related client-certificate flows
- retrieving the leaf certificate or available X.509 chain
- obtaining a `crypto.Signer` backed by the underlying native key handle, token, or database

It is not intended for:

- SSH keys or SSH certificates
- generic key management or secret storage
- creating a universal abstraction over every possible credential store
- hiding backend-specific configuration that the application should choose explicitly

## Convenience Boundary

This package keeps the library/application boundary explicit.

The library handles:

- backend access
- identity enumeration
- identity selection helpers
- signer construction
- TLS client-certificate integration helpers

The application is expected to handle:

- how to discover modules, profiles, or tokens
- which backend to use in a given environment
- how to collect credentials or passwords from users
- how to choose defaults and present UX
- any environment-specific convenience behavior

That is why backends such as PKCS#11 and NSS require explicit module/profile
configuration instead of embedding discovery or prompting policy in the library.

## Backend Resolution

`Open(context.Background())` with no options uses the native backend for the current platform.

On Linux, that native path returns `ErrUnsupportedBackend` because there is no
single standard system client-certificate store for this library to target.

`Open(context.Background(), WithBackend(BackendAuto), ...)` follows these rules:

- macOS and Windows use the native backend by default
- any PKCS#11 option switches resolution to the PKCS#11 backend family, and the module path then becomes required
- any NSS option switches resolution to the NSS backend family, and both module path and profile directory then become required
- on Windows, `WithWindowsStoreLocation` / `WithWindowsStoreName` select the system store (default CurrentUser\\MY)
- Windows store options cannot be combined with PKCS#11 or NSS options

Opening a LocalMachine store read-only does not inherently require elevation.
Access to a certificate's private key depends on that key's ACL; creating or
modifying LocalMachine stores and certificates commonly requires elevated
permissions.

## Selection Semantics

Helpers that select a single identity return one best match, not all matches.

- `FindTLSCertificate` returns one TLS client certificate
- `NewClientCertificateSource` / `ClientCertificateFunc` / `GetClientCertificateFunc` return one certificate per handshake callback
- `FindIdentity` returns one best-ranked identity
- `FindIdentities` / `FilterIdentities` return all matching identities

When more than one identity matches, the current ranking:

- ranks identities known to be hardware-backed above other matches when requested
- gives a smaller bonus to currently valid certificates
- also favors certificates with later expiry

This is a scoring heuristic, not a strict lexicographic guarantee.

Set `SelectOptions.RequireCurrentlyValid` to reject expired or not-yet-valid
certificates instead of merely accounting for validity during ranking.
`ClientCertificateSource` always requires currently valid certificates, so it
will not cache or re-select an identity outside its validity window.

If you need to inspect every matching identity, use `FindIdentities`.

## Metadata Semantics

Metadata quality depends on the backend.

- Native backends expose generic identity metadata such as backend name, key type, label, and a cert-derived URI
- PKCS#11 also exposes token-specific metadata through `PKCS11IdentityInfo`
- NSS also exposes backend-specific metadata through `NSSIdentityInfo`

Capability metadata also has two levels:

- `IdentityInfo` exposes compatibility booleans such as `IsHardwareBacked()`
- `IdentityCapabilityInfo` exposes tri-state values so callers can distinguish `yes`, `no`, and `unknown`

Prefer `IdentityCapabilityInfo` when you need to distinguish `no` from `unknown`.

## Error Handling

The most useful exported errors to branch on are:

- `ErrIdentityNotFound` when no identity matches the current filters
- `ErrCredentialRequired` when a backend requires credentials or reports a credential state problem
- `ErrIncorrectCredential` when backend credentials were supplied but rejected
- `ErrUnsupportedBackend` when a backend is unavailable on the current platform or not implemented
- `ErrClosed` when a signer or resource is used after explicit cleanup

## Docs

- [PKCS#11 Usage](docs/pkcs11.md)
- [NSS Usage](docs/nss.md)
- [Examples](docs/examples.md)

## Runnable examples

Runnable programs are available under `examples/`.

None of the examples perform a live TLS handshake or dial a remote server.
Use `examples/mtls-source` as the template for long-lived `tls.Config` wiring,
then plug that config into your own `tls.Dial` or `http.Transport`.

See [docs/examples.md](docs/examples.md) for runnable commands and PKCS#11/NSS flag usage.

## Local checks

- `make check` runs the library test suite on the current host
- `make lint` runs `golangci-lint` (also enforced in CI)
- `make check-macos` runs `make check` and then the macOS native integration test
- `make check-linux` runs the Linux preflight in Docker and is mainly useful on non-Linux hosts

CI runs lint on Ubuntu, `go test -race ./...` on Linux, and platform tests plus example builds on Linux, macOS, and Windows.

On Linux, prefer `make check` directly unless you specifically want Docker-based parity with the CI environment.

## Credits

- macOS implementation inspired by [getvictor/mtls](https://github.com/getvictor/mtls)

## License

MIT
