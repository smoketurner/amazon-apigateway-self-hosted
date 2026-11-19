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
- **`/ping` and `/sping`** are reserved on every domain and answer `200` with `healthy`.
- **REST and HTTP APIs** can be mapped to the same domain. Mappings do not say which kind an API
  is, so each API ID is looked up as a REST API first.
- **Certificates:** a client that asks for a domain name (SNI) gets that domain's certificate from
  `--domain-cert-dir`, exact names before wildcards; everything else gets `--tls-cert`.
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

A REST stage with `cacheClusterEnabled` caches responses in the state backend (per replica, in
memory, until a shared backend is configured), so no cache cluster is provisioned or billed.

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
