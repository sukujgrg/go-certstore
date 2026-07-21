# NSS Usage

This document describes explicit NSS backend usage with `go-certstore`.

## Understand the boundary

The NSS backend requires explicit configuration.

The library requires:

- an NSS `softokn3` module path
- an NSS profile or database directory
- an application-supplied credential callback when the database requires one

The library does not:

- find Firefox profiles
- find the NSS module
- prompt the user directly

The application makes those decisions.

## Open an NSS profile

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

`WithNSSProfileDir` accepts either:

- a plain directory path such as `/path/to/nssdb`
- an explicit NSS database specification such as `sql:/path/to/nssdb` or `dbm:/path/to/nssdb`

If you pass a plain directory, the library treats it as an `sql:` database.

## Select identities

After the store is open, use the normal helper APIs:

```go
ident, err := certstore.FindIdentity(ctx, store, certstore.FindIdentityOptions{
    Backend:   certstore.BackendNSS,
    SubjectCN: "client.example.com",
    ValidOnly: true,
})
if err != nil {
    return err
}
defer ident.Close()
```

For TLS client selection, open the store one time and use
`NewClientCertificateSource`. Handshakes then reuse cached certificates and
signers:

```go
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

source := certstore.NewClientCertificateSource(ctx, store, certstore.SelectOptions{
    SubjectCN:            "client.example.com",
    RequireClientAuthEKU: true,
})
defer source.Close()

tlsConfig := &tls.Config{
    GetClientCertificate: source.GetClientCertificate,
}
```

Prefer this method over `GetClientCertificateFunc`. That helper opens NSS for
each handshake. It can leave token sessions waiting for garbage collection.

The source caches returned certificates across handshakes. It skips expired
cache entries when it selects again. It keeps previously returned signers alive
until `Close` for handshakes that are still in progress.

The source does not monitor the profile for replaced identities. Recreate the
source when the application must load a new certificate. As an alternative,
keep the process lifetime aligned with the certificate lifetime.

Token-backed signers can reuse the context from `Identity.Signer(ctx)` for
later re-authentication. The source reuses the context from construction. Go's
TLS hook does not supply a context for each handshake.

## Use identity metadata

NSS identities supply:

- generic metadata through `IdentityInfo`
- capability metadata with `yes`, `no`, or `unknown` through `IdentityCapabilityInfo`
- NSS-specific metadata through `NSSIdentityInfo`

Example:

```go
if info, ok := ident.(certstore.NSSIdentityInfo); ok {
    fmt.Println("Profile:", info.ProfileDir())
    fmt.Println("Module:", info.ModulePath())
    fmt.Println("Token:", info.TokenLabel())
}
```

## Run the examples

All runnable examples in `examples/` support `-backend nss`.

List identities:

```sh
go run ./examples/list-identities \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb
```

Inspect TLS selection:

```sh
go run ./examples/tls-client \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb \
  -subject "client.example.com"
```

Use the recommended long-lived mTLS source:

```sh
go run ./examples/mtls-source \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb \
  -subject "client.example.com"
```

Export a certificate:

```sh
go run ./examples/export-cert \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb \
  -subject "client.example.com" \
  -chain
```

## Test locally without Firefox

You do not need Firefox to test the NSS backend.

You can create a standalone NSS database, import a test identity, and point
`go-certstore` at that database.

### 1. Install NSS command-line tools

macOS:

```sh
brew install nss
```

Ubuntu/Debian:

```sh
sudo apt install libnss3-tools
```

Fedora/RHEL:

```sh
sudo dnf install nss-tools
```

### 2. Create an NSS database

```sh
mkdir -p /tmp/nssdb
certutil -N -d sql:/tmp/nssdb --empty-password
```

### 3. Create a test certificate

```sh
openssl req -newkey rsa:2048 -nodes -x509 \
  -keyout /tmp/nss-key.pem \
  -out /tmp/nss-cert.pem \
  -days 365 \
  -subj "/CN=nss-client.example.com"
```

### 4. Convert it to PKCS#12 and import it

```sh
openssl pkcs12 -export \
  -inkey /tmp/nss-key.pem \
  -in /tmp/nss-cert.pem \
  -out /tmp/nss-client.p12 \
  -name "nss-client" \
  -passout pass:
```

```sh
pk12util -i /tmp/nss-client.p12 -d sql:/tmp/nssdb -W ""
```

### 5. Verify the database contents

```sh
certutil -L -d sql:/tmp/nssdb
```

### 6. Find the `softokn3` module path

macOS:

```sh
find /opt/homebrew -name 'libsoftokn3*.dylib' 2>/dev/null
find /usr/local -name 'libsoftokn3*.dylib' 2>/dev/null
```

Linux:

```sh
find /usr -name 'libsoftokn3.so' 2>/dev/null
```

### 7. Run the examples against the standalone NSS database

```sh
go run ./examples/list-identities \
  -backend nss \
  -module /path/to/libsoftokn3.so_or_dylib \
  -profile /tmp/nssdb
```

```sh
go run ./examples/tls-client \
  -backend nss \
  -module /path/to/libsoftokn3.so_or_dylib \
  -profile /tmp/nssdb \
  -subject "nss-client.example.com"
```

```sh
go run ./examples/mtls-source \
  -backend nss \
  -module /path/to/libsoftokn3.so_or_dylib \
  -profile /tmp/nssdb \
  -subject "nss-client.example.com"
```

```sh
go run ./examples/export-cert \
  -backend nss \
  -module /path/to/libsoftokn3.so_or_dylib \
  -profile /tmp/nssdb \
  -subject "nss-client.example.com" \
  -chain
```

### Use a password-protected NSS database

To test credential handling, create a new database. Do not reuse the
empty-password database from the earlier steps.

```sh
mkdir -p /tmp/nssdb-pass
printf 'secret123\n' > /tmp/nss-pass.txt
certutil -N -d sql:/tmp/nssdb-pass -f /tmp/nss-pass.txt
pk12util -i /tmp/nss-client.p12 -d sql:/tmp/nssdb-pass -K secret123 -W ""
```

Then run the examples with:

```sh
CERTSTORE_PIN=secret123 go run ./examples/list-identities \
  -backend nss \
  -module /path/to/libsoftokn3.so_or_dylib \
  -profile /tmp/nssdb-pass
```

The examples accept `-pin`, `CERTSTORE_PIN`, or `PKCS11_PIN`. The library still
expects the application to supply credentials through
`WithCredentialPrompt(...)`.

The callback returns `[]byte`, not a `string`. The library clears that buffer
after use. The library also clears the buffer if the callback returns an error.
If secret lifetime is important, return a dedicated buffer. Do not return a
shared slice that other code will use again.

The package passes a temporary string view to the NSS dependency. The cgo
runtime or the dependency can make an internal copy. This method is not a
high-assurance secret-memory system.

### Pass a profile argument

Pass either:

- `/tmp/nssdb`
- `sql:/tmp/nssdb`

If you pass a plain directory path, the library treats it as an `sql:` NSS
database.
