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
| `AWS_PROXY` (Lambda) integrations | Invoked with the API Gateway proxy event, payload format 1.0 or 2.0 |
| `MOCK` integrations | Status, literal response headers, and response template returned (templates are not evaluated as VTL) |
| Stage variables | Read from the stage and substituted into integration URIs; overridable locally |
| Lambda authorizers | `TOKEN` and `REQUEST` (REST), `REQUEST` with payload 1.0/2.0 and simple responses (HTTP): invoked, cached by identity source, and the returned policy evaluated per method; `--insecure-skip-authorization` skips them |
| Cognito/JWT authorizers | **Not evaluated yet.** Answer `401` unless `--insecure-skip-authorization` is set |
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
| `--replicas` | `APIGW_REPLICAS` | `1` | Gateway replicas serving the API; throttle rates and bursts are divided by this because each replica keeps its own buckets ([parity](docs/parity.md#throttling-caching-and-releases)) |
| `--proxy-protocol` | `APIGW_PROXY_PROTOCOL` | off | Require a PROXY protocol v2 header on `--listen`, from `--trusted-proxies` only |
| `--access-logs` | `APIGW_ACCESS_LOGS` | `aws` | `aws` writes to the stage's access log destination, `stdout` writes lines to standard output, `off` writes none ([Observability](#observability)) |
| `--execution-logs` | `APIGW_EXECUTION_LOGS` | `aws` | Same choices, for `loggingLevel`/`dataTraceEnabled` execution logs |
| `--metrics-log-group` | `APIGW_METRICS_LOG_GROUP` | none | CloudWatch Logs log group (must exist) that receives metrics as embedded metric format events; metrics are off when unset |
| `--metrics-namespace` | `APIGW_METRICS_NAMESPACE` | `ApiGatewaySelfHosted` | CloudWatch namespace for the metrics (`AWS/` is reserved) |
| `--tracing` | `APIGW_TRACING` | `aws` | `aws` sends X-Ray segments for stages with tracing enabled and propagates trace headers; `off` does neither |
| `--xray-sampling-percent` | `APIGW_XRAY_SAMPLING_PERCENT` | `5` | Percentage of requests traced after the first request each second, when the caller made no sampling decision |
| `--domain-name NAME` | `APIGW_DOMAIN_NAMES` | none | Serve every API mapped to this custom domain (repeatable or comma-separated; `*.example.com` allowed) instead of one API ([Custom domains](#custom-domains)) |
| `--domain-cert-dir DIR` | `APIGW_DOMAIN_CERT_DIR` | none | `DIR/{domain}/tls.crt` and `tls.key` per domain, served by SNI and reloaded on change; without it `--tls-cert` serves every domain |
| `--canary-export-stage` | `APIGW_CANARY_EXPORT_STAGE` | none | REST stage that holds the canary deployment of `--stage`, exported to build the canary release ([Canary releases](#canary-releases)) |
| `--log-stream` | `APIGW_LOG_STREAM` | `{HOSTNAME}/{start time}/{suffix}` | Log stream this process writes to in every log group |

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

## Custom domains

`--domain-name api.example.com` replaces `--rest-api-id`/`--http-api-id`: the process serves every
API stage mapped to that custom domain in API Gateway, reading the domain's API mappings (and, for
domains in a routing rule mode, its routing rules) and keeping them current every
`--refresh-seconds`. The request's `Host` selects the domain; unknown hosts and requests no mapping
matches answer `403 {"message":"Forbidden"}`.

- **API mappings** are matched as API Gateway documents: with only single-level keys a request
  goes to the mapping named by its first path segment, else the `(none)` mapping; when any key has
  several levels, the longest matching prefix wins (`/ordersandmore` goes to `orders`). The matched
  key is removed from the path, so `/orders/shop/5/hats` reaches the API as `/hats`.
- **Routing rules** (`ROUTING_RULE_ONLY`, `ROUTING_RULE_THEN_API_MAPPING`) are evaluated by
  ascending priority: header conditions (name case-insensitive, value case-sensitive, a `*`
  wildcard at the start and/or end), a base path condition, and `stripBasePath`. A rule or mapping
  whose API fails to load answers 503 until it loads.
- **`/ping` and `/sping`** are reserved on every domain and answer `200` with `healthy`.
- **REST and HTTP APIs** can be mapped to the same domain. Mappings do not say which kind an API
  is, so each API ID is looked up as a REST API first.
- **Certificates:** a client that asks for a domain name (SNI) gets that domain's certificate from
  `--domain-cert-dir`, exact names before wildcards; everything else gets `--tls-cert`.
- **Not supported with `--domain-name`:** `--stage`, `--base-path`, `--integration-overrides`,
  `--config-cache`, and `--canary-export-stage` (each API serves its stage's deployment; a
  stage with a canary serves both releases as in single-API mode).

`/routes` lists each domain's mode, mappings, and loaded APIs.

## Canary releases

A REST stage with canary settings serves two releases. Each request goes to the canary with
probability `percentTraffic` (chosen with aws-lc-rs randomness; if randomness is unavailable the
request goes to production), and the canary's `stageVariableOverrides` apply to its routes on top of
the stage's variables. `--stage-variable` overrides apply to both releases and win over the
canary's, so a variable you override locally is the same in both. `$context.isCanaryRequest` is
`true` or `false` on stages that have a canary. Canary requests are also logged to the
`{access log group}/Canary` and `API-Gateway-Execution-Logs_{apiId}/{stage}/Canary` log groups
(created if missing) and counted in a second metric series whose `Stage` is `{stage}/Canary`.
A canary at 0 percent builds no second release.

API Gateway cannot export a canary deployment, so by default the canary release has the stage's
routes and differs only in stage variables. To serve the canary deployment's routes, deploy it to
a second stage of the same API (for example with `create-deployment --stage-name canary-shadow`)
and pass `--canary-export-stage canary-shadow`: that stage's export builds the canary release
whenever either stage's deployment changes, and its own stage variables and settings are ignored.
`/routes` reports the canary release, its routes, and where its structure came from. `useStageCache`
is recorded and applied when response caching lands ([#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38)).

## Observability

Everything below is configured on the API Gateway stage, as on API Gateway itself, and applies
without a redeploy of this container when the stage changes.

**Access logs.** The stage's access log format is a template of `$context.*` variables
(`$context.requestId`, `$context.identity.sourceIp`, `$context.status`,
`$context.responseLength`, `$context.responseLatency`, `$context.integrationLatency`, ...),
so CLF, JSON, XML, and CSV formats all work. A variable with no value renders as `-`, and
values are JSON-escaped, so JSON formats stay valid. `$context.responseLength` is the
`Content-Length` of the response and is `-` for streamed responses of unknown length.
The destination ARN decides where lines go: a CloudWatch Logs log group
(`arn:aws:logs:...:log-group:NAME`, which must exist) or a Firehose delivery stream
(`arn:aws:firehose:...:deliverystream/amazon-apigateway-NAME`, records are newline-terminated).
Anything else, or a stage with no destination, writes to standard output. A batch the
destination rejects is written to standard output too.

**Log streams.** Each process writes to its own stream in every CloudWatch Logs log group:
`{HOSTNAME}/{start time}/{8 hex characters}`, so pods never share a stream and streams sort by
start time. `--log-stream` sets a fixed name.

**Metrics.** CloudWatch Logs extracts the metrics from embedded metric format events, so they
are published to the log group in `--metrics-log-group` under `--metrics-namespace`. REST
APIs publish `Count`, `4XXError`, `5XXError`, `Latency`, and `IntegrationLatency` with
dimensions `ApiName, Stage`; with `metricsEnabled` on a method (or `*/*`) they also publish
`ApiName, Method, Resource, Stage`. HTTP APIs publish `Count`, `4xx`, `5xx`, `Latency`,
`IntegrationLatency` with `ApiId, Stage`, and with detailed metrics `ApiId, Method, Resource,
Stage`. One event per series is written each minute, so the statistics differ from
`AWS/ApiGateway`: use `Sum` for `Count` and the error metrics (`Average` and `SampleCount` do
not mean what they do there), and treat `Latency`/`IntegrationLatency` percentiles and maxima as
estimates, because each minute publishes at most 100 sampled values.

**Execution logs.** REST stages with `loggingLevel` `ERROR` or `INFO` write a request trace to
`API-Gateway-Execution-Logs_{apiId}/{stage}` (created if missing). `dataTraceEnabled` adds the
query string and request headers (`Authorization`, `X-Api-Key`, and `Cookie` values are
redacted). Request and response bodies are not logged, and events are cut at 1 KB as in API
Gateway. HTTP APIs have no execution logs.

**X-Ray.** REST stages with tracing enabled send one segment per sampled request (named
`{API name}/{stage}`, origin `AWS::ApiGateway::Stage`, with the request, the response status, and
`error`/`throttle`/`fault` flags) with `PutTraceSegments`. The trace comes from the caller's
`X-Amzn-Trace-Id` or W3C `traceparent` when present, including its sampling decision, and is
otherwise started here and sampled by X-Ray's default rule (the first request each second, then
`--xray-sampling-percent`); X-Ray's sampling rules are not fetched. Integrations receive
`X-Amzn-Trace-Id: Root=...;Parent={this gateway's segment};Sampled=...` (HTTP backends and
Lambda, per call) and, for HTTP backends, `traceparent`. The segment has no subsegment for the
integration call, and API Gateway's passive mode (segments only when a caller traced) is not
reproduced. A stage without tracing leaves trace headers untouched.

**Delivery.** Each destination has a bounded queue (10,000 events). When it is full the newest
events are dropped and counted in a warning, so a slow destination never slows requests. Queues
are flushed every 5 seconds, when a batch is full, and at shutdown.

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
| `apigateway:GET` | the same two resources for the stage named by `--canary-export-stage` | canary releases from a shadow stage |
| `apigateway:GET` | `arn:aws:apigateway:<region>::/apis/<id>/exports/OAS30`, `.../apis/<id>/stages/<stage>` | HTTP APIs |
| `apigateway:GET` | `arn:aws:apigateway:<region>::/v2/domainnames/<domain>`, `.../apimappings`, `.../routingrules`, `arn:aws:apigateway:<region>::/restapis/<id>` | `--domain-name` |
| `lambda:InvokeFunction` | each integrated function and each Lambda authorizer function | `AWS_PROXY` routes and Lambda authorizers |
| `sts:AssumeRole` | each integration `credentials` and each `authorizerCredentials` role | integrations and authorizers with a role, unless `--integration-credentials=gateway` |
| `logs:CreateLogStream`, `logs:PutLogEvents` | each access log group, the metrics log group, and `arn:aws:logs:<region>:<account>:log-group:API-Gateway-Execution-Logs_<id>/<stage>:*` | access logs, metrics, execution logs |
| `logs:CreateLogGroup` | `arn:aws:logs:<region>:<account>:log-group:API-Gateway-Execution-Logs_*`, and each access log group with `/Canary` appended | execution logs, and canary access logs (the only log groups the gateway creates) |
| `xray:PutTraceSegments` | `*` | stages with tracing enabled |
| `firehose:PutRecordBatch` | each access log delivery stream | access logs to Firehose |

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
