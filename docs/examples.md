# Examples

Runnable example programs live under `examples/`.

## Available examples

- `examples/list-identities`
  - Enumerate identities from the default backend or PKCS#11
  - Print label, backend, key type, hardware-backed status, and certificate summary
  - Can filter by `-subject`, `-issuer`, and `-valid`
- `examples/tls-client`
  - Select a TLS client certificate using `FindTLSCertificate`
  - Prints richer selection and rejection diagnostics
  - Supports PKCS#11 options through flags/environment
  - This example does not open a network connection
  - It simulates local certificate selection only, so you can see which identity would be chosen before wiring `GetClientCertificateFunc` into a real `tls.Config`
- `examples/export-cert`
  - Select one matching identity and write the leaf certificate or full chain as PEM
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

The examples accept either `-pin` or `PKCS11_PIN`.

## Run the TLS helper example

What it does:

- Opens the selected backend
- Filters for a client-auth-capable identity using `FindTLSCertificate`
- Prints the selected certificate and chain, or explains why each candidate was rejected
- Does not perform a real TLS handshake
- Does not verify whether a particular server would accept the certificate

Use this example to inspect local client-certificate selection behavior.

When more than one identity matches, this example returns the same single
best-ranked certificate that `FindTLSCertificate` would return. If you want to
see all matching identities for a subject or issuer, use `examples/list-identities`.

```sh
export PKCS11_PIN=123456

go run ./examples/tls-client \
  -backend pkcs11 \
  -module "$SOFTHSM2_MODULE" \
  -token "go-certstore-test" \
  -subject "pkcs11-client.example.com"
```

The examples accept either `-pin` or `PKCS11_PIN`.

For `-backend auto`, pass at least one filter such as `-subject` or `-issuer`.
The example intentionally refuses to auto-pick an arbitrary native-store
certificate without a filter.

## Run the export example

What it does:

- Opens the selected backend
- Selects one best-ranked identity using `FindIdentity`
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
