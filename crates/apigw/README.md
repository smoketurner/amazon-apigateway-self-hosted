# apigw

The gateway binary. It downloads an existing Amazon API Gateway REST or HTTP API's OpenAPI
export, builds an axum router from it, serves it over TLS, and swaps the router live as the API
changes.

```bash
cargo run --bin apigw -- --openapi-file api.json --api-type rest \
  --tls-cert cert.pem --tls-key key.pem
```

Items are `pub(crate)`: this crate is not a library. Mapping templates and Java regular
expressions come from [`apigw-vtl`](../apigw-vtl) and [`apigw-regex`](../apigw-regex), and IAM
Roles Anywhere credentials from [`aws-rolesanywhere-credentials`](../aws-rolesanywhere-credentials).

## Documentation

- [README](../../README.md) — what it serves and a quick start
- [architecture.md](../../docs/architecture.md) — module map and request flow
- [configuration.md](../../docs/configuration.md) — every flag and environment variable
- [deployment.md](../../docs/deployment.md) — Helm, packages, Kubernetes and Istio
- [parity.md](../../docs/parity.md) — feature matrix and known differences from API Gateway
- [crypto.md](../../docs/crypto.md) — TLS and the aws-lc-rs provider

## Tests

```bash
cargo test -p apigw
```

Tests need no AWS access. `tests/fixtures` holds sample REST and HTTP exports and recorded
request-validation errors. `build_never_panics` (proptest) checks that no API definition can
crash route building.
