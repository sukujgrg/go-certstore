# Examples

Runnable example programs live under `examples/`.

## Available examples

- `examples/list-identities`
  - Enumerate identities from the default backend or PKCS#11
  - Print label, backend, key type, hardware-backed status, and certificate summary
- `examples/tls-client`
  - Build a `tls.Config.GetClientCertificate` callback with `GetClientCertificateFunc`
  - Supports PKCS#11 options through flags/environment

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

```sh
export PKCS11_PIN=123456

go run ./examples/tls-client \
  -backend pkcs11 \
  -module "$SOFTHSM2_MODULE" \
  -token "go-certstore-test" \
  -subject "pkcs11-client.example.com"
```

The examples accept either `-pin` or `PKCS11_PIN`.
