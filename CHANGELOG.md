# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `--valkey-url` (and `--valkey-ca-cert`) keep throttle buckets, usage-plan quotas, and cached
  authorizer results in a Valkey or Redis-compatible server shared by every replica, so limits are
  exact across the fleet and `--replicas` no longer divides them. TLS (`rediss://`) is recommended and
  `redis://` warns. Every call has a 500 ms timeout; when the server is unreachable requests are
  admitted and cached results are recomputed.
- API keys and usage plans are enforced for REST APIs. A method that requires a key admits an enabled
  key that belongs to a usage plan of the stage (`403 Forbidden` otherwise), with the key taken from
  `x-api-key` or, for key source `AUTHORIZER`, from the Lambda authorizer's `usageIdentifierKey`. The
  plan's throttles (plan-wide and per method) and day/week/month quotas count each key and answer
  `429`. Keys are read with their values, held only as SHA-256 hashes, and refreshed every
  `--usage-refresh-seconds` with paged reads paced for the control plane's rate limit. Authorizer
  results no longer hold the `usageIdentifierKey` in the cache.
- REST binary media types: Lambda proxy events carry a request body as base64 when its
  `Content-Type` matches `binaryMediaTypes` (exact, `type/*`, `*/*`) and as text otherwise, and a
  function's base64 response is decoded only when the client's first `Accept` media type matches
  (the response `Content-Type` when there is no `Accept`). `contentHandling` is no longer reported
  for proxy integrations, where it has no effect.
- REST payload compression: with `minimumCompressionSize`, buffered responses at least that large
  are compressed for clients accepting `gzip` or `deflate` (the highest-weighted coding must be one
  API Gateway supports), and `gzip`/`deflate` request bodies are decompressed before the
  integration sees them. Adds the `flate2` dependency (pure Rust backend).

- `crates/apigw-vtl`: an Apache Velocity 1.7 engine for mapping templates. It parses and renders
  references, `#set`, `#if`/`#elseif`/`#else`, `#foreach` (1,000-iteration cap, `$foreach.*`,
  `$velocityCount`), `#break`, `#stop`, comments, escaping, and Velocity's whitespace gobbling,
  with a Java value model (`toString`, arithmetic, comparison) and the common `String`, `List`,
  and `Map` methods. `$input` (`body`, `json()`, `path()`, `params()`), `$util`, `$context`
  (including caller-readable `requestOverride`/`responseOverride`), and `$stageVariables` are
  provided, with Jayway JsonPath semantics for paths. Output size, evaluation steps, and nesting
  are bounded and reported as typed errors. Its tests replay about 960 templates rendered by
  Apache Velocity 1.7 and Jayway JsonPath 2.9, and a cargo-fuzz target lives in `fuzz/`.
- `tools/vtl-oracle`: a Docker-run Java oracle (Apache Velocity 1.7, Jayway JsonPath 2.9, pinned
  by digest and checksum) with a committed corpus of about 9,500 templates and their expected
  output. `apigw-vtl`'s `oracle` test replays it, and `.github/workflows/vtl-oracle.yml` re-renders
  it weekly, replays fresh random templates, and fuzzes the template, JSON path, and regex
  parsers.

- Resource policies are evaluated as API Gateway evaluates them: an explicit `Deny` ends the request
  before authentication, then the policy is combined with the authorizer's decision per the
  authorization-flow tables (no authorizer, Lambda authorizer, Cognito user pool). `aws:SourceIp`
  (`IpAddress`, `NotIpAddress`), `aws:UserAgent`, `aws:Referer`, `aws:SecureTransport`, and date
  conditions are evaluated against the trusted client address; conditions that cannot be decided
  count as matching for a `Deny` and not matching for an `Allow`. Denials answer `403` with AWS's
  message.
- Cognito user pool authorizers (REST) and JWT authorizers (HTTP APIs) are evaluated. Tokens are
  verified (RS256/RS384/RS512) against the issuer's published keys, fetched over HTTPS with a 1.5 s
  timeout and 150 KB cap, cached for two hours, and refreshed at most every 30 s when a token names an
  unknown key. Issuer, audience, expiry, and scopes are checked, and claims reach `$context.authorizer`.
  `--issuer-endpoint` fetches an issuer's keys from a mirror instead.
- REST header behavior from API Gateway's documented header table: request headers API Gateway
  drops never reach `HTTP_PROXY` backends or Lambda, backend and Lambda response headers are
  dropped or renamed to `X-Amzn-Remapped-*`, `X-HTTP-Method-Override` replaces the method before
  routing, and `;` splits query strings. `HTTP_PROXY` requests gain `x-amzn-apigateway-api-id`,
  a default `User-Agent`, `X-Forwarded-Proto`, and `X-Forwarded-Port`. HTTP APIs send `Forwarded`
  in place of `X-Forwarded-*` and a `Content-Type` on body-less requests.
- `HTTP_PROXY` `tlsConfig`: `insecureSkipVerification` and `serverNameToVerify` (verification and
  SNI against that name, connecting to the integration's own host), with a client cached per
  server name and address set. The unenforced-feature report no longer lists it.
- Integration timeouts are bounded as API Gateway bounds them: at least 50 ms, REST not capped at 29
  s, HTTP APIs at 30 s.
- Request-size quotas: REST URLs over 10,240 characters answer `414` and REST headers over 20,480
  bytes `431`; HTTP API request line plus headers over 10,240 bytes answer `431`. HTTP/2 header
  lists up to 64 KiB reach the check instead of being refused by hyper at 16 KiB.

- Lambda authorizers are evaluated. REST `TOKEN` (with `identityValidationExpression`) and `REQUEST`
  authorizers and HTTP API `REQUEST` authorizers (payload 1.0 and 2.0, simple responses) are invoked
  with the request's identity sources, their results are cached by identity source and TTL, and the
  returned IAM policy is evaluated against each method ARN, including `*` and `?` wildcards. A
  missing identity source answers `401`, a denying policy `403`, a failing or invalid authorizer
  `500`; `principalId` and `context` reach `$context.authorizer` and Lambda events. Cognito and JWT
  authorizers still answer `401`.
- `crates/apigw-regex`: a `java.util.regex` translator for `fancy-regex` covering whole-string
  `matches`, ASCII `\w \d \s \b`, Java line terminators for `.` `^` `$`, flags, `\Q..\E`, POSIX
  classes, replacement strings with greedy `$n` and `${name}`, and `split` limits. Constructs
  that cannot be translated are rejected with a typed error and evaluation stops at a
  configurable backtrack limit. Tested against fixtures generated by real Java
  (`tools/java-regex-oracle`).
- `docs/parity.md`, a feature matrix of what `apigw` supports, partially supports, plans (with issue
  links), or cannot do, for REST and HTTP APIs.
- Requests run through an explicit `Pipeline` in API Gateway's stage order, carrying a
  `RequestContext` that owns the `$context` variables used by events and, later, templates,
  gateway responses, and access logs.
- Lambda integrations invoke in the region from the function ARN (previously `AWS_REGION`),
  run as the integration's `credentials` role when it has one (`--integration-credentials`),
  propagate `X-Amzn-Trace-Id`, and can be pointed at a Runtime Interface Emulator with
  `--lambda-endpoint`. `/routes` reports the outcome of every role assumption.
- `--trusted-proxies` / `--trusted-proxy-hops` (`APIGW_TRUSTED_PROXIES`,
  `APIGW_TRUSTED_PROXY_HOPS`): the client address behind Istio or a load balancer is read from
  `X-Forwarded-For`, walking from the right, but only when the TCP peer is a trusted proxy.
  `sourceIp` in Lambda events reports it.
- `--proxy-protocol` (`APIGW_PROXY_PROTOCOL`): require a PROXY protocol v2 header on the API
  listener from trusted proxies, with a 5 second header timeout.
- Istio `X-Forwarded-Client-Cert` is parsed (Subject, Hash, URI/DNS SANs, `Cert`) from trusted
  proxies and kept with the client identity for upcoming mTLS support.

- Access logs: the stage's `$context` format (CLF, JSON, XML, CSV, or any template) is
  rendered for every request, including ones no route matched, and written in batches to the
  stage's CloudWatch Logs log group (one log stream per process) or Firehose delivery stream,
  with standard output as the fallback (`--access-logs`).
- Metrics: `Count`, `4XXError`, `5XXError`, `Latency`, and `IntegrationLatency` (HTTP APIs:
  `4xx`, `5xx`) are aggregated per minute and published as CloudWatch embedded metric format
  events to `--metrics-log-group` under `--metrics-namespace` (default `ApiGatewaySelfHosted`),
  with `ApiName`/`Stage` (HTTP: `ApiId`/`Stage`) dimensions and per-route `Method`/`Resource`
  dimensions when the stage enables detailed metrics.
- Execution logs: REST stages with `loggingLevel` `ERROR` or `INFO` (and `dataTraceEnabled`)
  write a request trace to `API-Gateway-Execution-Logs_{apiId}/{stage}` (`--execution-logs`).
- X-Ray: REST stages with tracing enabled send one segment per sampled request with
  `PutTraceSegments`. A caller's `X-Amzn-Trace-Id` (or W3C `traceparent`) is continued and its
  sampling decision honored; otherwise X-Ray's default rule applies (the first request each
  second, then `--xray-sampling-percent`, default 5). The trace is passed on per request in
  `X-Amzn-Trace-Id` (HTTP backends and Lambda) and `traceparent` (HTTP backends), with this
  gateway's segment as the parent, and `$context.xrayTraceId` is available to access logs.
  `--tracing off` disables all of it.
- Canary releases: a REST stage with canary settings serves a second release to
  `percentTraffic` percent of requests, chosen at random per request, with the canary's stage
  variable overrides applied (local `--stage-variable` overrides still win). `$context.isCanaryRequest`
  is `true` or `false` on stages with a canary. Canary requests are also written to the
  `{log group}/Canary` access and execution log groups and counted under `Stage` `{stage}/Canary`.
  `--canary-export-stage` names a stage holding the canary deployment, whose export builds the
  canary's routes; `/routes` reports the canary release.
- Custom domains: `--domain-name` (repeatable, wildcards allowed) serves every API stage mapped to
  a custom domain from one process. The `Host` picks the domain; the domain's routing mode picks
  how: API mappings (single- and multi-level keys, longest prefix, the `(none)` mapping) and/or
  routing rules (header and base path conditions, priorities, `stripBasePath`). The matched
  prefix is removed from the path. REST and HTTP APIs can share a domain, each API refreshes
  on its own, and `/ping` and `/sping` answer 200 as on API Gateway. `--domain-cert-dir` serves
  each domain its own certificate by SNI, reloaded when the files change. `/routes` lists each
  domain's mappings and APIs.
- Mutual TLS: a custom domain with a `mutualTlsAuthentication` truststore requires client
  certificates. The CA bundle is read from S3 (`truststoreUri` at `truststoreVersion`) and
  re-read on every refresh; clients must present a certificate chained to it, unexpired, in the
  TLS handshake, and requests to the domain from a client that did not (for example one that asked
  for a different name in SNI) are refused. A domain whose truststore cannot be loaded refuses
  every connection rather than serving unverified. `$context.identity.clientCert.*` (access logs),
  and `requestContext.identity.clientCert` and `requestContext.authentication.clientCert` in
  Lambda events, carry `clientCertPem`, `subjectDN`, `issuerDN`, `serialNumber`, and `validity`;
  a certificate reported by a trusted proxy in `X-Forwarded-Client-Cert` is described the same way.
- Response caching: REST stages with `cacheClusterEnabled` cache responses of methods whose method
  settings enable caching (`GET` methods through the stage-wide setting, other methods only through
  their own), for the method's TTL (default 300 s, at most 3600 s, 0 off), in the state backend. Entries
  are keyed by the method and the integration's `cacheKeyParameters` values, and responses over
  1,048,576 bytes are not cached. `Cache-Control: max-age=0` follows
  `requireAuthorizationForCacheControl` (default true) and
  `unauthorizedCacheControlHeaderStrategy`; since this gateway cannot verify the IAM permission to
  invalidate, every such request counts as unauthorized when authorization is required.
  `CacheHitCount` and `CacheMissCount` are published with the other metrics. A canary release uses
  the stage cache only with `useStageCache`, sharing entries only when it runs the same deployment.
- Log delivery uses bounded queues that drop (and count) events instead of slowing requests,
  and flushes everything on shutdown.
- REST gateway responses: every error the gateway generates (missing authentication token,
  invalid API key, unauthorized, integration failure and timeout, 413, and the rest) uses API
  Gateway's default status and message and applies the API's customizations from
  `x-amazon-apigateway-gateway-responses`: status code, `gatewayresponse.header.*` parameters
  (literals, `context.*`, `method.request.*`, `stageVariables.*`), and body templates with simple
  `$context`, `$stageVariables`, and `$method.request.*` substitution (no VTL), with
  `DEFAULT_4XX`/`DEFAULT_5XX` fallback. Error responses carry `x-amzn-ErrorType` and
  `x-amz-apigw-id`. The 413 response is not customizable. HTTP APIs keep fixed messages.
- Lambda proxy events match API Gateway's `requestContext`: `accountId` (from the function
  ARN), `extendedRequestId`, `resourceId`, the full `identity` block, and `protocol`
  (REST reports `HTTP/1.1` as API Gateway documents; HTTP APIs report the client's version).
  REST payload 1.0 keeps the client's header name case (recovered from the HTTP/1 request
  head, because hyper keeps it private); HTTP/2 clients and HTTP APIs get lower case.
- Lambda integrations reject requests and buffered responses over Lambda's 6 MB limit with
  `502`, merge `headers` and `multiValueHeaders` as API Gateway does, tolerate `null` response
  fields, and drop `Content-Length`/hop-by-hop headers set by the function.
- `--lambda-endpoint` accepts `name:alias`, a function ARN with or without its qualifier, or the
  bare name, most specific first.
- REST response streaming: `responseTransferMode: STREAM` with Lambda
  (`InvokeWithResponseStream`, `/response-streaming-invocations` URIs) and `HTTP_PROXY`, with
  the 15 minute limit, a 5 minute idle limit, and `$context.integration.responseTransferMode`
  / `timeToAllHeaders`. Output that doesn't follow the streaming format answers `500`.

- Stage throttling: REST `methodSettings` (including the `*/*` default) and HTTP API route
  settings (including the default route settings) limit each method or route with a token
  bucket and answer `429` (`THROTTLED` gateway response for REST, `{"message":"Too Many
  Requests"}` for HTTP). `--replicas` (`APIGW_REPLICAS`) divides the limits per replica.
- A `StateBackend` (in-memory, bounded, with LRU eviction) holding token buckets, calendar-aligned
  day/week/month quota counters, and a TTL cache, for usage plans and response caching to use.

- HTTP API CORS: preflight requests are answered with `204` from the configured CORS rules
  without calling the integration (after the route's own protections), and allowed origins get
  the CORS response headers; the backend's own CORS headers are dropped.
- HTTP API parameter mapping for `HTTP_PROXY` integrations: `append:`, `overwrite:`, and
  `remove:` for headers, query strings, and the path, and per-status response mappings
  including `overwrite:statuscode`, with `$request.*`, `$response.*`, `$context.*`,
  `$stageVariables.*`, and static sources.

- `--vpc-link CONNECTION_ID=URL` (`APIGW_VPC_LINKS`, repeatable) serves `HTTP_PROXY`
  integrations that use a VPC link from an in-cluster URL; REST routes send the integration
  URI's host as the `Host` header, HTTP API routes send the request path (with the stage prefix
  API Gateway adds). Routes whose link has no mapping still answer `501`, now naming the flag.

### Removed

- `--unsupported-resource-policy` (`APIGW_UNSUPPORTED_RESOURCE_POLICY`): resource policies are
  evaluated, so routes no longer answer `403` for every policy. A policy that cannot be read still
  refuses its routes.

### Changed

- HTTP API route selection takes the method into account: a route that matches the path but
  not the method is skipped for a less specific route that serves it, as in API Gateway's
  documented priorities. Previously such requests fell through to `$default`.
- HTTP APIs never run request validation, even if a hand-written definition names a validator.
- Lambda authorizer results are cached in the state backend under a SHA-256 hash of the identity
  sources instead of in a private cache that held the caller's token.
- An `HTTP_PROXY` backend that cannot be reached now answers REST clients 504 `Network error
  communicating with endpoint` (`INTEGRATION_FAILURE`) instead of 502; an invalid integration URI
  answers 500 (`API_CONFIGURATION_ERROR`).
- `$context.extendedRequestId` is a 12-character token, the same value as the `x-amz-apigw-id`
  response header.
- `requestParameters` mappings accept `context.*` and `stageVariables.*` sources.
- Access logs, execution logs, detailed metrics, tracing, and canary settings are no longer
  listed as unenforced on `/routes`.
- `X-Forwarded-For` sent by a client that is not a trusted proxy is no longer forwarded to
  `HTTP_PROXY` integrations: it is replaced by the client's address. `X-Forwarded-Client-Cert` is
  removed from such requests. Set `--trusted-proxies` to keep forwarding a proxy's headers.
- `terraform/`: Terraform modules and a `dev` environment that deploy REGIONAL REST and HTTP reference APIs
  (plus an echo Lambda, authorizers, Cognito, service targets, and a GitHub OIDC role) to measure
  parity against real API Gateway. See `terraform/README.md`.
- `ApiModel`: the export and `GetStage` are imported into one typed model covering
  integrations (all fields, `$ref` resolution), request parameters and bodies, validators,
  authorizers, models, gateway responses, binary media types, compression, API key source,
  CORS, resource policy, and stage settings (method/route settings, access logs, tracing,
  canary, caching). `/routes` lists every imported feature that is not enforced yet.
- Refresh calls `GetStage` first and re-downloads the export only when the deployment changed;
  failed refreshes back off exponentially with jitter.
- `crates/apigw-parity`, a dev tool with `record` (capture the reference APIs' behavior as
  normalized, redacted fixtures) and `replay` (serve the recorded export with `apigw` and diff
  its answers). Seed cases and hand-written fixtures live in `parity/`; CI runs `replay`, and
  `.github/workflows/parity.yml` re-records nightly and opens an issue on drift. Replay serves
  `AWS_PROXY` routes through an in-process Lambda endpoint (`--lambda-endpoint`), so Lambda event
  shapes for payload formats 1.0 and 2.0 are covered.

### Fixed

- Resource policies and request validators were silently ignored because the REST export did
  not request them. The export now uses `extensions=apigateway,authorizers`; routes under a
  resource policy answer 403 and routes with a request validator answer 501 until those
  features are supported (`--unsupported-resource-policy` / `--unsupported-validation`
  `=ignore` to serve them). `--insecure-skip-authorization` does not skip resource policies.
- API key routes answer `403 Forbidden` and REST `AWS_IAM` routes `403 Missing Authentication
  Token`, matching API Gateway, instead of 401.
- REST APIs no longer apply a document-level `security` block to every method.
- HTTP API sources require `--stage`; without it the export was the latest, possibly
  undeployed, configuration.
