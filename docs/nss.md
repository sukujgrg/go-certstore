# NSS Usage

This document covers explicit NSS backend usage with `go-certstore`.

## Boundary

The NSS backend is intentionally explicit.

The library requires:

- an NSS `softokn3` module path
- an NSS profile/database directory
- an application-provided credential callback when the database requires one

The library does not:

- discover Firefox profiles for you
- locate the NSS module for you
- prompt the user directly

Those decisions belong in the application that uses this library.

## Open an NSS profile

```go
ctx := context.Background()
store, err := certstore.Open(ctx,
    certstore.WithBackend(certstore.BackendNSS),
    certstore.WithNSSModule("/path/to/libsoftokn3.so"),
    certstore.WithNSSProfileDir("/path/to/nssdb"),
    certstore.WithCredentialPrompt(func(info certstore.PromptInfo) (string, error) {
        return os.Getenv("CERTSTORE_PIN"), nil
    }),
)
if err != nil {
    return err
}
defer store.Close()
```

`WithNSSProfileDir` accepts either:

- a plain directory path such as `/path/to/nssdb`
- an explicit NSS database spec such as `sql:/path/to/nssdb` or `dbm:/path/to/nssdb`

If you pass a plain directory, the library treats it as an `sql:` database.

## Selecting identities

Once the store is open, the normal helper APIs apply:

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

For TLS client selection:

```go
tlsConfig := &tls.Config{
    GetClientCertificate: certstore.GetClientCertificateFunc(
        ctx,
        []certstore.Option{
            certstore.WithBackend(certstore.BackendNSS),
            certstore.WithNSSModule("/path/to/libsoftokn3.so"),
            certstore.WithNSSProfileDir("/path/to/nssdb"),
            certstore.WithCredentialPrompt(func(info certstore.PromptInfo) (string, error) {
                return os.Getenv("CERTSTORE_PIN"), nil
            }),
        },
        certstore.SelectOptions{
            SubjectCN:            "client.example.com",
            RequireClientAuthEKU: true,
        },
    ),
}
```

## Metadata

NSS identities expose:

- generic metadata through `IdentityInfo`
- tri-state capability metadata through `IdentityCapabilityInfo`
- NSS-specific metadata through `NSSIdentityInfo`

For example:

```go
if info, ok := ident.(certstore.NSSIdentityInfo); ok {
    fmt.Println("Profile:", info.ProfileDir())
    fmt.Println("Module:", info.ModulePath())
    fmt.Println("Token:", info.TokenLabel())
}
```

## Runnable examples

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

Export a certificate:

```sh
go run ./examples/export-cert \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb \
  -subject "client.example.com" \
  -chain
```

## Local testing without Firefox

You do not need Firefox installed to test the NSS backend.

You can create a standalone NSS database, import a test identity, and point
`go-certstore` at that database directly.

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

### 7. Run the examples against the standalone NSS DB

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
go run ./examples/export-cert \
  -backend nss \
  -module /path/to/libsoftokn3.so_or_dylib \
  -profile /tmp/nssdb \
  -subject "nss-client.example.com" \
  -chain
```

### Password-protected NSS DBs

If you want to test credential handling instead of using an empty-password DB:

```sh
printf 'secret123\n' > /tmp/nss-pass.txt
certutil -N -d sql:/tmp/nssdb -f /tmp/nss-pass.txt
pk12util -i /tmp/nss-client.p12 -d sql:/tmp/nssdb -K secret123 -W ""
```

Then run the examples with:

```sh
CERTSTORE_PIN=secret123 go run ./examples/list-identities \
  -backend nss \
  -module /path/to/libsoftokn3.so_or_dylib \
  -profile /tmp/nssdb
```

The examples accept `-pin` or `CERTSTORE_PIN`, but the library itself still
expects the application to provide credentials through
`WithCredentialPrompt(...)`.

### Profile argument detail

Pass either:

- `/tmp/nssdb`
- `sql:/tmp/nssdb`

If you pass a plain directory path, the library treats it as an `sql:` NSS
database automatically.
