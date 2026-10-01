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

| API Gateway feature | Behavior in `apigw` |
|---|---|
| Resource paths, `{param}`, greedy `{proxy+}`, `ANY`, HTTP API `$default` | Routed exactly as API Gateway routes them |
| `HTTP_PROXY` integrations | Forwarded, streaming the response; `requestParameters` path/query/header mappings and `timeoutInMillis` honored |
| `AWS_PROXY` (Lambda) integrations | Invoked with the API Gateway proxy event, payload format 1.0 or 2.0, including qualified ARNs and aliases; REST payload 1.0 keeps the client's header case; 6 MB request/response limit (`502`) |
| REST response streaming (`responseTransferMode: STREAM`) | Lambda via `InvokeWithResponseStream` (`.../response-streaming-invocations` URIs, metadata + 8 null bytes + payload), and `HTTP_PROXY`; up to 15 minutes, 5 minute idle limit |
| `MOCK` integrations | Status, literal response headers, and response template returned (templates are not evaluated as VTL) |
| Stage variables | Read from the stage and substituted into integration URIs; overridable locally |
| Lambda/Cognito/JWT authorizers | **Not evaluated yet.** Answer `401` unless `--insecure-skip-authorization` is set |
| API keys | **Not checked yet.** Answer `403 Forbidden` unless `--insecure-skip-authorization` is set |
| IAM (`AWS_IAM`) auth | Cannot be verified outside AWS. REST answers `403 Missing Authentication Token`, HTTP `403 Forbidden`, unless `--insecure-skip-authorization` is set |
| Resource policies | **Not evaluated yet.** Every route of an API with a policy answers `403` unless `--unsupported-resource-policy=ignore` (not affected by `--insecure-skip-authorization`) |
| Request validators | **Not run yet.** Validated routes answer `501` unless `--unsupported-validation=ignore` |
| `AWS`/`HTTP` (non-proxy, VTL mapping templates), VPC links | Answer `501`; listed with the reason on `/routes` |
| Unknown route | REST: `403 {"message":"Missing Authentication Token"}`; HTTP: `404 {"message":"Not Found"}` |

The full feature matrix, with an issue link for every gap, is in [docs/parity.md](docs/parity.md).

`/routes` on the admin listener lists, per route, its protections, any problems, and any
imported settings not enforced yet, plus the API-wide settings not enforced yet.

Every response carries a request ID (`x-amzn-requestid` for REST APIs, `apigw-requestid` for
HTTP APIs).

## Quick start

```bash
# TLS is mandatory; any PEM certificate and key work.
apigw \
  --rest-api-id a1b2c3d4e5 --stage prod \
  --tls-cert /etc/apigw/tls/tls.crt --tls-key /etc/apigw/tls/tls.key
```

Every flag has an environment variable (`apigw --help` lists them). The main ones:

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--rest-api-id` + `--stage` | `APIGW_REST_API_ID`, `APIGW_STAGE` | | Mirror a REST API stage |
| `--http-api-id` + `--stage` | `APIGW_HTTP_API_ID`, `APIGW_STAGE` | | Mirror an HTTP API stage (the deployed configuration) |
| `--openapi-file` + `--api-type` | `APIGW_OPENAPI_FILE` | `rest` | Serve an export from disk (no AWS calls for config) |
| `--tls-cert`, `--tls-key` | `APIGW_TLS_CERT`, `APIGW_TLS_KEY` | required | PEM files; reloaded automatically when they change |
| `--listen` | `APIGW_LISTEN` | `0.0.0.0:8443` | API traffic |
| `--admin-listen` | `APIGW_ADMIN_LISTEN` | off | `/healthz` and `/routes` (also TLS) |
| `--base-path` | `APIGW_BASE_PATH` | none | Serve under `/prod` etc., like an `execute-api` URL |
| `--refresh-seconds` | `APIGW_REFRESH_SECONDS` | `60` | Re-download interval; `0` disables |
| `--config-cache` | `APIGW_CONFIG_CACHE` | none | Last-known-good definition, used when AWS is unreachable at startup |
| `--stage-variable NAME=VALUE` | `APIGW_STAGE_VARIABLE_<NAME>` | | Override a stage variable |
| `--integration-overrides` | `APIGW_INTEGRATION_OVERRIDES` | none | Re-point individual routes (below) |
| `--insecure-skip-authorization` | `APIGW_INSECURE_SKIP_AUTHORIZATION` | off | Serve authorizer, API key, and IAM routes without checking credentials |
| `--integration-credentials` | `APIGW_INTEGRATION_CREDENTIALS` | `assume` | `assume` runs integrations as their `credentials` role; `gateway` uses the gateway's own credentials |
| `--lambda-endpoint FUNCTION=URL` | `APIGW_LAMBDA_ENDPOINTS` | none | Invoke a function at a URL speaking Lambda's Invoke protocol (e.g. the Runtime Interface Emulator in-cluster) |
| `--unsupported-resource-policy` | `APIGW_UNSUPPORTED_RESOURCE_POLICY` | `reject` | `ignore` serves APIs with resource policies unrestricted |
| `--unsupported-validation` | `APIGW_UNSUPPORTED_VALIDATION` | `reject` | `ignore` forwards requests without running request validators |
| `--trusted-proxies` | `APIGW_TRUSTED_PROXIES` | none | Comma-separated CIDRs or addresses of proxies whose `X-Forwarded-For` and `X-Forwarded-Client-Cert` are believed ([Client IP](docs/deployment.md#client-ip)) |
| `--trusted-proxy-hops` | `APIGW_TRUSTED_PROXY_HOPS` | `1` | Proxies between the client and `apigw`, counting the one that connects to it |
| `--proxy-protocol` | `APIGW_PROXY_PROTOCOL` | off | Require a PROXY protocol v2 header on `--listen`, from `--trusted-proxies` only |

Logs are JSON on stdout by default (`--log-format text` for humans); filter with `RUST_LOG`.

## Pointing routes at different targets

The paths always come from API Gateway. The targets can be changed locally, two ways.

**Stage variables** are API Gateway's own per-environment mechanism. If an integration URI is
`http://${stageVariables.petsHost}/pets/{id}`, set `APIGW_STAGE_VARIABLE_petsHost=pets.default.svc:8080`.

**Integration overrides** replace a route's integration outright, keyed by route key, using
the same shape as `x-amazon-apigateway-integration`. This can turn a Lambda route into an
HTTP route:

```json
{
  "GET /pets/{petId}": {
    "type": "http_proxy",
    "httpMethod": "GET",
    "uri": "http://pets.default.svc:8080/pets/{petId}"
  },
  "ANY /orders/{proxy+}": {
    "type": "http_proxy",
    "uri": "http://orders.default.svc:8080/{proxy}"
  }
}
```

The file is re-read on every refresh. A key that names no route rejects the whole update (the
previous routes keep serving), so a typo never goes unnoticed.

## Refresh and failure behavior

- A refresh that fails (AWS unreachable, invalid definition, bad override file) keeps the
  current routes and logs the error once per distinct bad input.
- A successful download is written to `--config-cache`. At startup, if API Gateway is
  unreachable, `apigw` starts from that cache.
- Requests in flight finish on the router they started with; new requests use the new one.

## AWS permissions

`apigw` uses the standard AWS credential chain (environment, shared config/profile,
`credential_process`, web identity). It needs:

| Action | Resource | For |
|---|---|---|
| `apigateway:GET` | `arn:aws:apigateway:<region>::/restapis/<id>/stages/<stage>/exports/oas30`, `.../restapis/<id>/stages/<stage>` | REST APIs |
| `apigateway:GET` | `arn:aws:apigateway:<region>::/apis/<id>/exports/OAS30`, `.../apis/<id>/stages/<stage>` | HTTP APIs |
| `lambda:InvokeFunction` | each integrated function (and its aliases) | `AWS_PROXY` routes; the same action covers `InvokeWithResponseStream` for streaming routes |
| `sts:AssumeRole` | each integration `credentials` role | integrations with a role, unless `--integration-credentials=gateway` |

## Documentation

| Doc | Covers |
|---|---|
| [docs/deployment.md](docs/deployment.md) | Container image, Kubernetes, Istio, certificates, credentials outside AWS |
| [docs/parity.md](docs/parity.md) | Feature matrix: what is supported, partial, planned, or not possible, for REST and HTTP APIs |
| [docs/architecture.md](docs/architecture.md) | Modules, request flow, the accept loop, router swapping |
| [docs/crypto.md](docs/crypto.md) | aws-lc-rs as the only crypto provider |
| [docs/ci-cd.md](docs/ci-cd.md) | CI jobs |
| [terraform/README.md](terraform/README.md) | Terraform modules and the `dev` environment that deploys the reference APIs parity is measured against |
| [parity/README.md](parity/README.md) | The parity runner: request cases, fixtures, `record` and `replay` |

## Development

```bash
make lint   # cargo clippy --workspace --all-targets --all-features -- -D warnings
make test   # cargo test --workspace --all-features
make deny   # cargo deny check
make parity # replay the recorded API Gateway fixtures against a local build
make image  # docker build -t apigw:local .
```

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your
option.
