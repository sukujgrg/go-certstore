# Examples

Runnable example programs live under `examples/`.

## Available examples

- `examples/list-identities`
  - Enumerate identities from the default backend or PKCS#11
  - Print label, backend, key type, hardware-backed status, and certificate summary
- `examples/tls-client`
  - Select a TLS client certificate using `FindTLSCertificate`
  - Prints richer selection and rejection diagnostics
  - Supports PKCS#11 options through flags/environment
  - This example does not open a network connection
  - It simulates local certificate selection only, so you can see which identity would be chosen before wiring `GetClientCertificateFunc` into a real `tls.Config`

## Run the list example

```sh
go run ./examples/list-identities
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
