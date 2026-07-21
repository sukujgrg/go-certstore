# Examples

The `examples/` directory contains runnable programs.

These programs do not start a live TLS handshake. They do not connect to a
remote server. Use `examples/mtls-source` as the model for long-lived
`tls.Config` setup.

Shared backend flag parsing lives in `examples/internal/cli`.

The examples accept `-pin`, `CERTSTORE_PIN`, or `PKCS11_PIN` when a backend
requires credentials.

On Linux, bare `-backend auto` fails because there is no native backend. Use
`-backend pkcs11` or `-backend nss`. You can also use `-backend auto` with
PKCS#11 options such as `-module` (and optionally `-token`) so auto resolves
to PKCS#11.

## Available examples

- `examples/list-identities`
  - Lists identities from the default backend, PKCS#11, or NSS
  - Prints the label, backend, key type, hardware-backed status, and certificate summary
  - Can filter by `-subject`, `-issuer`, and `-valid`
- `examples/tls-client`
  - Selects a TLS client certificate with `FindTLSCertificate`
  - Prints selection and rejection details
  - Supports PKCS#11 and NSS through flags and environment variables
  - Does not open a network connection
  - Simulates local certificate selection only, so you can see which identity the library would select before you wire `NewClientCertificateSource(ctx, store, ...)` into a real `tls.Config`
- `examples/mtls-source`
  - Shows the recommended long-lived pattern: `Open` → `NewClientCertificateSource` → `tls.Config.GetClientCertificate` → `Close`
  - Calls `GetClientCertificate` two times to show certificate and signer cache reuse
  - Supports PKCS#11 and NSS through flags and environment variables
  - Does not connect to a remote server
- `examples/export-cert`
  - Selects one matching identity and writes the leaf certificate or full chain as PEM
  - Supports `-subject`, `-issuer`, `-chain`, and `-out`

## Run the list example

```sh
go run ./examples/list-identities
```

Filter by subject or issuer:

```sh
go run ./examples/list-identities -subject "client.example.com"
go run ./examples/list-identities -issuer "My Issuing CA"
```

With PKCS#11:

```sh
export PKCS11_PIN=123456

go run ./examples/list-identities \
  -backend pkcs11 \
  -module "$SOFTHSM2_MODULE" \
  -token "go-certstore-test"
```

With NSS:

```sh
export CERTSTORE_PIN=123456

go run ./examples/list-identities \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb
```

With `-backend auto`, `-module` is the PKCS#11 module path. Use `-backend nss`
when the module path is an NSS `softokn3` library.

## Run the TLS helper example

This example:

- Opens the selected backend
- Filters for a client-auth identity with `FindTLSCertificate`
- Prints the selected certificate and chain, or explains why each candidate was rejected
- Does not start a real TLS handshake
- Does not check whether a server would accept the certificate

Use this example to inspect local client-certificate selection.

When more than one identity matches, this example returns the same best-ranked
certificate that `FindTLSCertificate` returns. To see all matching identities
for a subject or issuer, use `examples/list-identities`.

```sh
export PKCS11_PIN=123456

go run ./examples/tls-client \
  -backend pkcs11 \
  -module "$SOFTHSM2_MODULE" \
  -token "go-certstore-test" \
  -subject "pkcs11-client.example.com"
```

With NSS:

```sh
export CERTSTORE_PIN=123456

go run ./examples/tls-client \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb \
  -subject "client.example.com"
```

For `-backend auto`, pass at least one filter such as `-subject` or `-issuer`.
The example does not select an arbitrary native-store certificate without a
filter.

## Run the mTLS source example

This example:

- Opens the selected backend one time
- Creates `NewClientCertificateSource` for long-lived TLS client authentication
- Builds a `tls.Config` with `GetClientCertificate: source.GetClientCertificate`
- Calls that callback two times to show cache reuse
- Closes the source and the store
- Does not start a real TLS handshake

Use this example as the model for token-backed mTLS clients.

```sh
export PKCS11_PIN=123456

go run ./examples/mtls-source \
  -backend pkcs11 \
  -module "$SOFTHSM2_MODULE" \
  -token "go-certstore-test" \
  -subject "pkcs11-client.example.com"
```

With NSS:

```sh
export CERTSTORE_PIN=123456

go run ./examples/mtls-source \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb \
  -subject "client.example.com"
```

## Run the export example

This example:

- Opens the selected backend
- Selects one best-ranked identity with `FindIdentity`
- Writes the leaf certificate or full chain as PEM
- Does not export the private key

```sh
go run ./examples/export-cert \
  -subject "client.example.com" \
  -out client-cert.pem
```

Export the full chain:

```sh
go run ./examples/export-cert \
  -subject "client.example.com" \
  -chain \
  -out client-chain.pem
```

Export from NSS:

```sh
go run ./examples/export-cert \
  -backend nss \
  -module /path/to/libsoftokn3.so \
  -profile /path/to/nssdb \
  -subject "client.example.com" \
  -chain \
  -out client-chain.pem
```
