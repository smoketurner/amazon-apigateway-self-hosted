# apigw — self-hosted Amazon API Gateway

`apigw` is a single Rust binary that serves the routes of an **existing** Amazon API
Gateway REST API (v1) or HTTP API (v2) from anywhere: a Kubernetes cluster on another cloud,
on-prem, or a laptop. It downloads the API's definition from API Gateway, builds an axum
router from it, and keeps the router current as the API changes. API Gateway remains the
place you design the API; `apigw` is a data-plane replica, in the spirit of Azure API
Management's
[self-hosted gateway](https://learn.microsoft.com/en-us/azure/api-management/self-hosted-gateway-overview).

```text
             GetExport / ExportApi (OpenAPI 3.0 + x-amazon-apigateway-* extensions)
 API Gateway ───────────────────────────────────────────────┐   every --refresh-seconds
                                                            ▼
 clients ──TLS──► apigw ──► axum router (swapped live) ──► HTTP backends
                                                       ├──► Lambda (Invoke)
                                                       └──► MOCK responses
```

## What it serves

- **Routing:** resource paths, `{param}`, greedy `{proxy+}`, `ANY`, and the HTTP API `$default`
  route, matched as API Gateway matches them.
- **Integrations:** `HTTP_PROXY`, `HTTP`, `MOCK`, Lambda (`AWS_PROXY`, payload 1.0 and 2.0,
  response streaming), AWS service integrations, and VPC links mapped to in-cluster URLs.
- **Mapping:** Velocity request and response templates, parameter mappings, stage variables,
  and gateway responses.
- **Authorization:** Lambda authorizers, Cognito and JWT authorizers, API keys and usage plans,
  resource policies, and request validators. Protected routes answer `401`/`403` unless the
  check passes; `AWS_IAM` cannot be verified outside AWS and is refused.
- **Stage features:** throttling, response caching, canary releases, custom domains with
  mutual TLS, access and execution logs, metrics, and X-Ray.

Anything that cannot be served faithfully answers `501` and is reported on `/routes`, never
approximated. [docs/parity.md](docs/parity.md) has the full feature matrix for REST and HTTP
APIs, including every known difference from API Gateway.

## Quick start

```bash
# TLS is mandatory; any PEM certificate and key work.
apigw \
  --rest-api-id a1b2c3d4e5 --stage prod \
  --tls-cert /etc/apigw/tls/tls.crt --tls-key /etc/apigw/tls/tls.key
```

Install it with Helm, the `.rpm` or `.deb` package, or the container image:
[docs/deployment.md](docs/deployment.md). It uses the standard AWS credential chain; the IAM
permissions it needs are listed [there](docs/deployment.md#aws-permissions).

The flags most deployments set (each has an environment variable; `apigw --help` lists all):

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--rest-api-id` + `--stage` | `APIGW_REST_API_ID`, `APIGW_STAGE` | | Mirror a REST API stage |
| `--http-api-id` + `--stage` | `APIGW_HTTP_API_ID`, `APIGW_STAGE` | | Mirror an HTTP API stage |
| `--domain-name` | `APIGW_DOMAIN_NAMES` | | Serve every API mapped to a custom domain instead of one API |
| `--openapi-file` + `--api-type` | `APIGW_OPENAPI_FILE` | `rest` | Serve an export from disk, with no AWS calls for configuration |
| `--tls-cert`, `--tls-key` | `APIGW_TLS_CERT`, `APIGW_TLS_KEY` | required | PEM files, reloaded when they change |
| `--listen` | `APIGW_LISTEN` | `0.0.0.0:8443` | API traffic |
| `--admin-listen` | `APIGW_ADMIN_LISTEN` | off | `/healthz`, `/routes`, and Prometheus `/metrics` (also TLS) |
| `--base-path` | `APIGW_BASE_PATH` | none | Serve under `/prod` etc., like an `execute-api` URL |
| `--refresh-seconds` | `APIGW_REFRESH_SECONDS` | `60` | How often to check API Gateway for changes; `0` disables |
| `--config-cache` | `APIGW_CONFIG_CACHE` | none | Last-known-good definition, used when AWS is unreachable at startup |

[docs/configuration.md](docs/configuration.md) lists every flag.

## Staying current with API Gateway

Every `--refresh-seconds` `apigw` reads the stage and compares its deployment and last change
with what it is serving. When either differs it downloads the definition again, builds a new
router, and swaps it in without a restart: requests in flight finish on the old router, new
ones use the new one. A refresh that fails (AWS unreachable, an invalid definition, a bad
override file) keeps the current routes serving.

`/routes` on the admin listener lists, per route, its integration, the role it runs as, its
protections, and any problems. Every response carries a request ID (`x-amzn-requestid` for REST
APIs, `apigw-requestid` for HTTP APIs).

## Documentation

| Doc | Covers |
|---|---|
| [docs/deployment.md](docs/deployment.md) | Installing with Helm, the `.rpm` and `.deb` packages, or the container image; Istio, certificates, credentials and IAM permissions |
| [docs/configuration.md](docs/configuration.md) | Every flag, stage variables and integration overrides, refresh and failure behavior |
| [docs/operations.md](docs/operations.md) | Custom domains and mutual TLS, canary releases, response caching, logs, CloudWatch and Prometheus metrics, X-Ray and OpenTelemetry tracing |
| [docs/parity.md](docs/parity.md) | Feature matrix: what is supported, partial, planned, or not possible, for REST and HTTP APIs |
| [docs/architecture.md](docs/architecture.md) | Modules, request flow, the accept loop, router swapping |
| [docs/crypto.md](docs/crypto.md) | aws-lc-rs as the only crypto provider |
| [docs/ci-cd.md](docs/ci-cd.md) | CI jobs and the release process |
| [terraform/README.md](terraform/README.md) | Terraform modules and the `dev` environment that deploys the reference APIs parity is measured against |
| [parity/README.md](parity/README.md) | The parity runner: request cases, fixtures, `record` and `replay` |

## Development

```bash
make lint   # cargo clippy --workspace --all-targets --all-features -- -D warnings
make test   # cargo test --workspace --all-features
make deny   # cargo deny check
make parity # replay the recorded API Gateway fixtures against a local build
make image  # docker build -t apigw:local .
make chart-lint  # lint the Helm chart and validate what it renders
```

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your
option.
