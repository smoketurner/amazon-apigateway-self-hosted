# Operations

Custom domains and mutual TLS, canary releases, response caching, and observability. Each is
configured in API Gateway, as on API Gateway itself; the flags that affect them are in
[configuration.md](configuration.md).

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
- **`/ping` and `/sping`** are reserved on every domain: `/ping` answers `200` with
  `Healthy Connection` and no `Content-Type`, `/sping` answers `200` with `healthy` and
  `Content-Type: null`, as API Gateway does.
- **REST and HTTP APIs** can be mapped to the same domain. Mappings do not say which kind an API
  is, so each API ID is looked up as a REST API first.
- **Certificates:** a client that asks for a domain name (SNI) gets that domain's certificate,
  exact names before wildcards; everything else gets `--tls-cert`. The certificate comes from
  `--domain-cert-dir`, or, with `--domain-cert-source acm`, from ACM (below).

**Certificates from ACM.** With `--domain-cert-source acm` the gateway serves the certificate API
Gateway serves for each domain, so clients see the same certificate from both. It reads the
certificate ARN from the domain (`domainNameConfigurations`), checks with `DescribeCertificate`
that the certificate is issued and was requested as
[exportable](https://docs.aws.amazon.com/acm/latest/userguide/acm-exportable-certificates.html),
and exports it with `ExportCertificate`. The export's passphrase is random, made for that one
export, and never leaves the process; the decrypted key is held in memory only and never
written to disk or to the configuration cache. On every refresh the gateway asks for the
certificate's serial number and exports again only when it changes (a renewal, or a different
certificate on the domain), so a domain costs about one export per renewal. The new certificate
takes effect for new connections. Until the first export succeeds the domain is served
`--tls-cert`; a failed export keeps the certificate already served. Both cases are logged,
counted in `apigw_tls_reloads_total{outcome="failure"}`, and shown on `/routes` under the domain's
`certificate` (`arn`, the `serial` being served, and the last `error`). Certificates requested
without the export option, and ACM public certificates issued before 2025-06-17, cannot be
exported.
- **Not supported with `--domain-name`:** `--stage`, `--base-path`, `--integration-overrides`,
  `--config-cache`, and `--canary-export-stage` (each API serves its stage's deployment; a
  stage with a canary serves both releases as in single-API mode).

`/routes` lists each domain's mode, mappings, whether it requires client certificates, and
loaded APIs.

**Mutual TLS.** A domain with a `mutualTlsAuthentication` truststore requires client certificates.
The truststore (`truststoreUri`, an `s3://bucket/key` PEM bundle of CA certificates, at
`truststoreVersion` when set) is read from S3 at startup and on every refresh, and a changed
bundle takes effect for new connections. Clients must present a certificate chained to a CA in the
bundle that is currently valid, with an algorithm rustls accepts (SHA-256 or stronger, RSA 2048 or
stronger, ECDSA); revocation is not checked, as on API Gateway. A client that fails verification
has its connection closed in the handshake (API Gateway answers 403). A domain whose truststore
cannot be loaded refuses every connection until it can, and requests whose `Host` names a mutual
TLS domain but whose connection did not present a verified certificate (for example a different
SNI name) answer `403`. Mutual TLS is verified by this gateway's own handshake, so put it behind a
TCP passthrough with PROXY protocol, not a proxy that terminates TLS; certificates a trusted
proxy forwards in `X-Forwarded-Client-Cert` are reported as `clientCert` but never satisfy a
domain's requirement.

The presented certificate is available as `$context.identity.clientCert.clientCertPem`,
`.subjectDN`, `.issuerDN`, `.serialNumber`, `.validity.notBefore`, and `.validity.notAfter`
(DNs as `C=US,O=Acme,CN=client`, dates as `May 28 12:30:02 2019 GMT`), in access logs, and in
Lambda events as `requestContext.identity.clientCert` (REST and payload 1.0) or
`requestContext.authentication.clientCert` (payload 2.0).

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
applies to [response caching](#response-caching): a canary uses the stage cache only with it,
and shares entries with production only when it runs the same deployment.

## Response caching

A REST stage with `cacheClusterEnabled` caches responses in the state backend, so no cache
cluster is provisioned or billed. Without `--valkey-url` each replica keeps its own entries in
memory. With it, replicas share entries through Valkey; a Valkey error or timeout is a cache
miss, and the response is served without being stored. Entries in Valkey are not encrypted,
whatever the stage's `cacheDataEncrypted` says
([#110](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/110)).

- **Which methods:** those whose method settings enable caching. As on API Gateway, the stage-wide
  `*/*` setting enables `GET` methods only; other methods need their own setting.
- **TTL:** the method setting's `cacheTtlInSeconds` (default 300, at most 3600; 0 turns caching off).
- **Key:** the method plus the values of the integration's `cacheKeyParameters` (method request
  headers, query string parameters, and path parameters, or integration request parameters mapped
  from them); an absent value is its own entry, and parameters that are not in the key do not
  separate entries. A method with no key parameters has one entry.
- **What is cached:** successful (2xx) responses of at most 1,048,576 bytes (status, headers, and
  body); the response is read before it is sent, so a cached route does not stream its first
  megabyte.
- **`Cache-Control: max-age=0`:** with `requireAuthorizationForCacheControl` (the default) the
  client must be authorized to invalidate, which needs IAM verification this gateway cannot do, so
  every such request is handled as unauthorized: `FAIL_WITH_403` answers `403`,
  `SUCCEED_WITH_RESPONSE_HEADER` (the default) serves the request normally with the header
  `Warning: 199 Cache-control headers were ignored because the caller was unauthorized.`, and
  `SUCCEED_WITHOUT_RESPONSE_HEADER` serves it silently. With `requireAuthorizationForCacheControl`
  off, any client's `max-age=0` request bypasses the cache and replaces the entry.
- **Metrics:** `CacheHitCount` and `CacheMissCount` are published for requests that used the
  cache ([Observability](#observability)).

## Observability

The stage's own settings (access logs, metrics, execution logs, X-Ray tracing) work as on API
Gateway and apply without a redeploy of this container when the stage changes. The gateway
also serves Prometheus metrics, and with `--otel` exports metrics and request spans with
OpenTelemetry; neither depends on the stage.

| Output | AWS destination | Standard output | Kubernetes / OpenTelemetry |
|---|---|---|---|
| Access logs | the stage's log group or Firehose stream (`--access-logs aws`) | `--access-logs stdout` | collect stdout |
| Execution logs | `API-Gateway-Execution-Logs_{apiId}/{stage}` (`--execution-logs aws`) | `--execution-logs stdout` | collect stdout |
| API Gateway metrics | embedded metric format events in `--metrics-log-group` | `--metrics stdout` (EMF lines) | `/metrics` (Prometheus), OTLP with `--otel` |
| Gateway health metrics | | | `/metrics` (Prometheus), OTLP with `--otel` |
| Traces | X-Ray segments (`--tracing aws`) | `--tracing stdout` (X-Ray segment JSON), `OTEL_TRACES_EXPORTER=console` (OpenTelemetry JSON) | OTLP spans with `--otel` |

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

**CloudWatch metrics.** API Gateway's metrics are written as embedded metric format events
under `--metrics-namespace`: to the log group in `--metrics-log-group`, where CloudWatch Logs
extracts them, or with `--metrics stdout` one JSON object per line on standard output, for the
CloudWatch agent, Container Insights, or Fluent Bit to forward to CloudWatch Logs. REST
APIs publish `Count`, `4XXError`, `5XXError`, `Latency`, and `IntegrationLatency` with
dimensions `ApiName, Stage`; with `metricsEnabled` on a method (or `*/*`) they also publish
`ApiName, Method, Resource, Stage`. HTTP APIs publish `Count`, `4xx`, `5xx`, `Latency`,
`IntegrationLatency`, and `DataProcessed` (request and response bytes of known length; bodies
streamed without a `Content-Length` are not counted) with `ApiId, Stage`, and with detailed
metrics `ApiId, Method, Resource, Stage`. One event per series is written each minute, so the
statistics differ from `AWS/ApiGateway`: use `Sum` for `Count`, the error metrics, and
`DataProcessed` (`Average` and `SampleCount` do not mean what they do there), and treat
`Latency`/`IntegrationLatency` percentiles and maxima as estimates, because each minute
publishes at most 100 sampled values.

**Execution logs.** REST stages with `loggingLevel` `ERROR` or `INFO` write a request trace to
`API-Gateway-Execution-Logs_{apiId}/{stage}` (created if missing) in API Gateway's wording:
the usage plan check (or that the method needs no API key, with the key masked to its last 6
characters), the start of execution, the method and resource, `Sending request to` the
endpoint, the integration's status and latency, `Successfully completed execution` or the
failure, and the method's status. `dataTraceEnabled` adds the method request path parameters,
query string, headers, and body; the endpoint request URI, headers, and body; the endpoint
response headers and body; and the method response body and headers. `Authorization`,
`Proxy-Authorization`, `X-Api-Key`, and `Cookie` values are redacted. Events are cut at 1 KB as
in API Gateway, and a body that does not fit ends in `[TRUNCATED]`. Bodies of responses
streamed to the client, and method response bodies larger than 1 MiB or of unknown length, are
not logged; authorizer steps are not logged. HTTP APIs have no execution logs.

**X-Ray.** REST stages with tracing enabled send one segment per sampled request (named
`{API name}/{stage}`, origin `AWS::ApiGateway::Stage`, with the request, the response status,
and `error`/`throttle`/`fault` flags) with `PutTraceSegments`, or write it to standard output
with `--tracing stdout`. A request that reached a backend has a subsegment for the
integration call: `remote`, named after the host, for HTTP backends (with the method, URL, and
status), and `aws` for Lambda (`Lambda`, with the function and region) and other AWS services
(named after the service). The trace comes from the caller's `X-Amzn-Trace-Id` or W3C
`traceparent` when present, including its sampling decision. Otherwise the request is sampled
by the account's X-Ray sampling rules, read with `GetSamplingRules` every five minutes from the
first traced stage, with the reservoir quotas `GetSamplingTargets` assigns every ten seconds
(rules match on the service name, `AWS::ApiGateway::Stage`, host, method, URL path, and the
stage ARN; rules with attributes never match). Until the rules are read, when they cannot be,
and with `--xray-sampling-rules false`, X-Ray's default rule applies: the first request each
second, then `--xray-sampling-percent`. Integrations receive
`X-Amzn-Trace-Id: Root=...;Parent={the integration subsegment};Sampled=...` (HTTP backends and
Lambda, per call) and, for HTTP backends, `traceparent`. With `--xray-passive`, stages without
tracing enabled record a segment for requests whose caller sampled them (`Sampled=1`, or a
sampled `traceparent`) and start no traces of their own, as API Gateway's passive mode does;
other requests' trace headers are left untouched, as on any stage without tracing.

**Delivery.** Each destination has a bounded queue (10,000 events). When it is full the newest
events are dropped and counted in a warning, so a slow destination never slows requests. Queues
are flushed every 5 seconds, when a batch is full, and at shutdown.

### Prometheus

`/metrics` on the admin listener (`--admin-listen`, TLS like every listener) serves the
gateway's metrics in the Prometheus text format. They are recorded for every API stage whatever
its settings. Labels are bounded: `route` is the route template (`/pets/{petId}`, `$default`, or
`(none)` for a request no route matched), never the request path; `method` is the route's
method, or for an `ANY` route the request's when it is one of `GET`, `PUT`, `POST`, `DELETE`,
`PATCH`, `HEAD`, `OPTIONS`, else `OTHER`. `stage` is `$default` for an API served without one.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `apigw_requests_total` | counter | `api_id`, `stage`, `method`, `route`, `status_class` | Requests answered, by `1xx` ... `5xx` |
| `apigw_request_duration_seconds` | histogram | `api_id`, `stage`, `method`, `route` | Time to the response headers (API Gateway's `Latency`) |
| `apigw_integration_duration_seconds` | histogram | `api_id`, `stage`, `method`, `route` | Time in the integration (`IntegrationLatency`) |
| `apigw_cache_hits_total`, `apigw_cache_misses_total` | counter | `api_id`, `stage`, `method`, `route` | Response cache hits and misses, for cached routes |
| `apigw_data_processed_bytes_total` | counter | `api_id`, `stage`, `method`, `route` | Request and response bytes of known length (`DataProcessed`) |
| `apigw_requests_in_flight` | gauge | | Requests on the API listener that have not been answered yet |
| `apigw_build_info` | gauge | `version`, `commit` | Always 1 |
| `apigw_api_info` | gauge | `api_id`, `stage`, `deployment_id` | Always 1 per loaded stage, naming the deployment being served |
| `apigw_routes`, `apigw_routes_unservable` | gauge | `api_id`, `stage` | Routes of each loaded stage, and those whose integration answers `501` |
| `apigw_config_refreshes_total` | counter | `api_id`, `stage`, `outcome` | Definition refreshes: `unchanged`, `swapped`, `fetch_failed`, `rejected` (the definition could not be built; the previous one keeps serving) |
| `apigw_config_last_success_timestamp_seconds` | gauge | `api_id`, `stage` | When the stage's definition was last loaded or found unchanged |
| `apigw_usage_refreshes_total` | counter | `api_id`, `stage`, `outcome` | Reads of API keys and usage plans: `success`, `failure` |
| `apigw_usage_last_success_timestamp_seconds` | gauge | `api_id`, `stage` | When they were last read |
| `apigw_tls_certificate_expiry_seconds` | gauge | `certificate` | Seconds until the `notAfter` of each served certificate (`default`, or the custom domain); negative once expired |
| `apigw_tls_reloads_total` | counter | `outcome` | Reloads of changed certificate files and certificates exported from ACM: `success`, `failure` (the previous certificate keeps serving) |
| `apigw_state_errors_total` | counter | `operation` | Valkey calls that failed or timed out: `take_token`, `consume_quota`, `cache_get`, `cache_put`, `cache_invalidate` |
| `apigw_authorizer_cache_hits_total`, `apigw_authorizer_cache_misses_total` | counter | `api_id`, `stage`, `authorizer` | Lambda authorizer results answered from the cache, and invocations for identities that were not cached |
| `apigw_jwks_fetches_total` | counter | `issuer`, `outcome` | Fetches of a token issuer's signing keys: `success`, `failure` |

`commit` is `unknown` for builds outside the release images. [deployment.md](deployment.md#monitoring)
lists the alerts worth setting.

### OpenTelemetry

`--otel` (`APIGW_OTEL=true`) exports the metrics above and a span per request with
OpenTelemetry, configured with the standard environment variables:

| Variable | Default | Effect |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_{TRACES,METRICS}_ENDPOINT` | `http://localhost:4318` (`:4317` for gRPC) | Collector address; `https://` endpoints are verified against the system roots, with aws-lc-rs |
| `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_{TRACES,METRICS}_PROTOCOL` | `http/protobuf` | `http/protobuf` or `grpc` |
| `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TIMEOUT` (and their per-signal forms) | | Passed to the exporter; compression is not built in |
| `OTEL_TRACES_EXPORTER` | `otlp` | `otlp`, `console` (one OTLP-JSON-shaped object per span on standard output), or `none` |
| `OTEL_METRICS_EXPORTER` | `otlp` | `otlp` or `none` (Prometheus is served either way) |
| `OTEL_METRIC_EXPORT_INTERVAL` | `60000` | Milliseconds between metric exports |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | `parentbased_always_on` | `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio` |
| `OTEL_SERVICE_NAME` | `apigw` | `service.name` |
| `OTEL_RESOURCE_ATTRIBUTES` | | More resource attributes; they override the detected ones below |

The resource carries `service.name`, `service.version` (the gateway's version), and, from
these environment variables when they are set (the Helm chart sets them from the downward
API), `k8s.pod.name` (`K8S_POD_NAME`), `k8s.pod.uid` (`K8S_POD_UID`, also
`service.instance.id`), `k8s.namespace.name` (`K8S_NAMESPACE_NAME`), `k8s.node.name`
(`K8S_NODE_NAME`), `k8s.container.name` (`K8S_CONTAINER_NAME`), and `k8s.deployment.name`
(`K8S_DEPLOYMENT_NAME`).

Each request has a server span named `{method} {route template}` (`{method}` when no route
matched) following the HTTP semantic conventions (`http.request.method`, `http.route`,
`url.path`, `url.scheme`, `server.address`, `client.address`, `user_agent.original`,
`http.response.status_code`, `http.response.body.size`, and `error.type` for 5xx responses,
which mark the span as an error) plus `apigw.api_id`, `apigw.stage`, and `apigw.request_id`.
Beneath it, `authorizer {name}` spans the route's authorizer (`apigw.authorizer.type`,
`apigw.authorizer.decision`: `allow`, `deny`, or `refused`) and `integration {type}` (a client
span with `apigw.integration.type`, `apigw.integration.target`, and the backend's
`http.response.status_code`) spans the integration call. The server span continues the
caller's W3C `traceparent` and `tracestate`, and HTTP integrations receive the integration
span as their `traceparent` (with the caller's `tracestate`), in place of the X-Ray-derived
`traceparent`. X-Ray tracing works alongside: `X-Amzn-Trace-Id` is still propagated, and a
caller's `traceparent` gives both the same trace ID.
