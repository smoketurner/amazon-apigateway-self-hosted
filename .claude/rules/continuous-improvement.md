# Continuous Improvement

Project-specific instructions for the `rust-ci-analyst` agent and the
`/rust-agents:continuous-improvement` skill.

## Test Configuration

Generate a local certificate once:

```bash
mkdir -p .local/testing && cd .local/testing && openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 30 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost
```

Run against an OpenAPI export on disk (no AWS access needed for configuration):

```bash
cargo run --bin apigw -- --openapi-file api.json --api-type rest \
  --tls-cert .local/testing/cert.pem --tls-key .local/testing/key.pem \
  --listen 127.0.0.1:8443 --admin-listen 127.0.0.1:9443 --log-format text
curl --cacert .local/testing/cert.pem https://localhost:8443/<path>
curl --cacert .local/testing/cert.pem https://localhost:9443/routes
```

Against a real API (requires AWS credentials and `AWS_REGION`):

```bash
cargo run --bin apigw -- --rest-api-id <id> --stage <stage> --tls-cert ... --tls-key ...
```

## Project Subsystems

- **source** — API Gateway export download, stage variables, last-known-good cache
- **spec** — OpenAPI + `x-amazon-apigateway-*` parsing, integration overrides
- **router** — path translation, conflict handling, live swapping, admin routes
- **integrations** — `HTTP_PROXY`, `AWS_PROXY` (Lambda), `MOCK`
- **listener** — TLS accept loop, timeouts, certificate reload

## Critical Paths

Live-test before any PR that touches them:

- Route building from real exports: conflicting or unusual paths must be skipped, never crash
- Refresh: a bad definition or override file keeps the current routes serving
- Certificate reload after the PEM files change
- Lambda payload 1.0/2.0 events and responses
- Authorization gate: protected routes answer 401 by default

The implementation rules are the review gates in [`code-standards.md`](code-standards.md).

## Reference Projects

- **vouch-sh/vouch** — the accept loop (`vouch-server/src/infra/accept.rs`) this listener follows
- **Azure API Management self-hosted gateway** — the operating model (cloud control plane,
  self-hosted data plane, config backup)

## Testing Notes

- Tests need no AWS access; the AWS SDK paths (`GetExport`, `ExportApi`, Lambda `Invoke`)
  are only exercised against a real account.
