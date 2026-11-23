# Configuration

Every flag, how to point routes at other targets, and how the gateway keeps its routes current.
For installing and running the gateway see [deployment.md](deployment.md).

## Flags

Every flag has an environment variable (`apigw --help` lists them). The main ones:

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--rest-api-id` + `--stage` | `APIGW_REST_API_ID`, `APIGW_STAGE` | | Mirror a REST API stage |
| `--http-api-id` + `--stage` | `APIGW_HTTP_API_ID`, `APIGW_STAGE` | | Mirror an HTTP API stage (the deployed configuration) |
| `--openapi-file` + `--api-type` | `APIGW_OPENAPI_FILE`, `APIGW_API_TYPE` | `rest` | Serve an export from disk (no AWS calls for config); `--api-type` is `rest` or `http` |
| `--tls-cert`, `--tls-key` | `APIGW_TLS_CERT`, `APIGW_TLS_KEY` | required | PEM files; reloaded automatically when they change |
| `--listen` | `APIGW_LISTEN` | `0.0.0.0:8443` | API traffic |
| `--max-connections` | `APIGW_MAX_CONNECTIONS` | `10000` | Connections served at once on each listener; further clients wait in the kernel's accept backlog |
| `--allowed-host` | `APIGW_ALLOWED_HOSTS` | any | Serve only these `Host` names (repeatable) and answer `403` to the rest, as API Gateway does for a host that is not the API's |
| `--admin-listen` | `APIGW_ADMIN_LISTEN` | off | `/healthz`, `/routes`, and Prometheus `/metrics` (also TLS) |
| `--base-path` | `APIGW_BASE_PATH` | none | Serve under `/prod` etc., like an `execute-api` URL |
| `--refresh-seconds` | `APIGW_REFRESH_SECONDS` | `60` | Re-download interval; `0` disables (refused with `--domain-cert-source acm`, which needs refreshes to export renewals) |
| `--config-cache` | `APIGW_CONFIG_CACHE` | none | Last-known-good definition, used when AWS is unreachable at startup |
| `--stage-variable NAME=VALUE` | `APIGW_STAGE_VARIABLE_<NAME>` | | Override a stage variable |
| `--integration-overrides` | `APIGW_INTEGRATION_OVERRIDES` | none | Re-point individual routes (below) |
| `--valkey-url` | `APIGW_VALKEY_URL` | unset | Valkey (or Redis-compatible) server holding throttle, usage-plan quota, authorizer-cache, and response-cache state, so every replica counts against the same limits and `--replicas` no longer divides them. Use `rediss://`; `redis://` is accepted with a warning. Credentials in the URL are never logged. Unset keeps per-replica in-memory state |
| `--valkey-ca-cert` | `APIGW_VALKEY_CA_CERT` | unset | PEM root certificate to trust for a `rediss://` server the system roots do not cover |
| `--usage-refresh-seconds` | `APIGW_USAGE_REFRESH_SECONDS` | `60` | Seconds between reads of API keys, usage plans, and their associations (0 reads once); reads are paced for the account's control-plane limit |
| `--insecure-skip-authorization` | `APIGW_INSECURE_SKIP_AUTHORIZATION` | off | Serve authorizer, API key, and IAM routes without checking credentials |
| `--integration-credentials` | `APIGW_INTEGRATION_CREDENTIALS` | `assume` | `assume` runs integrations as their `credentials` role; `gateway` uses the gateway's own credentials |
| `--vpc-link CONNECTION_ID=URL` | `APIGW_VPC_LINKS` | none | Serve a VPC link's integrations from an in-cluster URL (repeatable; [VPC links](deployment.md#vpc-links)) |
| `--issuer-endpoint ISSUER=URL` | `APIGW_ISSUER_ENDPOINTS` | none | Fetch a token issuer's signing keys from URL instead of from the issuer (an in-cluster mirror of the identity provider); plain `http` URLs are allowed and logged as a warning |
| `--lambda-endpoint FUNCTION=URL` | `APIGW_LAMBDA_ENDPOINTS` | none | Invoke a function at a URL speaking Lambda's Invoke protocol (e.g. the Runtime Interface Emulator in-cluster) |
| `--aws-endpoint SERVICE=URL` | `APIGW_AWS_ENDPOINTS` | none | Send REST `AWS` integrations and HTTP API integration subtypes for `SERVICE` (`sqs`, `sns`, `dynamodb`, `states`, `kinesis`, `events`, `s3`, or `appconfig`) to a URL instead of the service's endpoint, such as LocalStack or an in-cluster mock (repeatable or comma-separated); requests are still signed |
| `--trusted-proxies` | `APIGW_TRUSTED_PROXIES` | none | Comma-separated CIDRs or addresses of proxies whose `X-Forwarded-For` and `X-Forwarded-Client-Cert` are believed ([Client IP](deployment.md#client-ip)) |
| `--trusted-proxy-hops` | `APIGW_TRUSTED_PROXY_HOPS` | `1` | Proxies between the client and `apigw`, counting the one that connects to it |
| `--replicas` | `APIGW_REPLICAS` | `1` | Gateway replicas serving the API; throttle rates and bursts are divided by this because each replica keeps its own buckets ([parity](parity.md#throttling-caching-and-releases)) |
| `--proxy-protocol` | `APIGW_PROXY_PROTOCOL` | off | Require a PROXY protocol v2 header on `--listen`, from `--trusted-proxies` only |
| `--access-logs` | `APIGW_ACCESS_LOGS` | `aws` | `aws` writes to the stage's access log destination, `stdout` writes lines to standard output, `off` writes none ([Observability](operations.md#observability)) |
| `--execution-logs` | `APIGW_EXECUTION_LOGS` | `aws` | Same choices, for `loggingLevel`/`dataTraceEnabled` execution logs |
| `--metrics` | `APIGW_METRICS` | `aws` | Where API Gateway's CloudWatch metrics go as embedded metric format events: `aws` writes to `--metrics-log-group` (none when it is unset), `stdout` writes one event per line to standard output, `off` writes none |
| `--metrics-log-group` | `APIGW_METRICS_LOG_GROUP` | none | CloudWatch Logs log group (must exist) that receives the metrics with `--metrics aws` |
| `--metrics-namespace` | `APIGW_METRICS_NAMESPACE` | `ApiGatewaySelfHosted` | CloudWatch namespace for the metrics (`AWS/` is reserved) |
| `--tracing` | `APIGW_TRACING` | `aws` | `aws` sends X-Ray segments for stages with tracing enabled and propagates trace headers; `stdout` writes the segments to standard output instead; `off` does neither |
| `--xray-sampling-rules` | `APIGW_XRAY_SAMPLING_RULES` | `true` | With `--tracing aws`, sample by the account's X-Ray sampling rules and reservoir quotas (`GetSamplingRules`, `GetSamplingTargets`); `false` applies only the default rule |
| `--xray-sampling-percent` | `APIGW_XRAY_SAMPLING_PERCENT` | `5` | Percentage of requests traced after the first request each second, when the caller made no sampling decision and no sampling rule applies |
| `--xray-passive` | `APIGW_XRAY_PASSIVE` | off | On stages without tracing enabled, trace the requests their caller sampled, and start no traces (X-Ray passive mode) |
| `--otel` | `APIGW_OTEL` | off | Export metrics and request spans with OpenTelemetry, configured with the standard `OTEL_*` variables ([OpenTelemetry](operations.md#opentelemetry)) |
| `--domain-name NAME` | `APIGW_DOMAIN_NAMES` | none | Serve every API mapped to this custom domain (repeatable or comma-separated; `*.example.com` allowed) instead of one API ([Custom domains](operations.md#custom-domains)) |
| `--domain-cert-dir DIR` | `APIGW_DOMAIN_CERT_DIR` | none | `DIR/{domain}/tls.crt` and `tls.key` per domain, served by SNI and reloaded on change; without it `--tls-cert` serves every domain |
| `--domain-cert-source` | `APIGW_DOMAIN_CERT_SOURCE` | `files` | `files` reads certificates from `--domain-cert-dir` (or serves `--tls-cert`); `acm` exports the ACM certificate API Gateway serves for each domain and follows its renewals ([Custom domains](operations.md#custom-domains)) |
| `--canary-export-stage` | `APIGW_CANARY_EXPORT_STAGE` | none | REST stage that holds the canary deployment of `--stage`, exported to build the canary release ([Canary releases](operations.md#canary-releases)) |
| `--log-stream` | `APIGW_LOG_STREAM` | `{HOSTNAME}/{start time}/{suffix}` | Log stream this process writes to in every log group |
| `--log-format` | `APIGW_LOG_FORMAT` | `json` | The gateway's own logs on standard output: `json`, or `text` for reading in a terminal |

Filter the gateway's own logs with `RUST_LOG`.

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
