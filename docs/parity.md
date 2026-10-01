# API Gateway parity

Which API Gateway features `apigw` reproduces, per API type. Statuses describe what the code on
`main` does today; every change that adds or removes behavior updates this file.

| Status | Meaning |
|---|---|
| **Supported** | Behaves as API Gateway does for what is listed |
| **Partial** | Works for the part described; the rest is tracked by the linked issue |
| **Planned** | Not implemented. The issue says when; the Behavior today column says what a request gets meanwhile |
| **Not possible** | Cannot be done outside AWS; the notes say what `apigw` does instead |
| **Out of scope** | A deliberate choice, not planned |

`REST` is a REST API (v1), `HTTP` an HTTP API (v2). A single status applies to both unless the
columns differ; `n/a` means the API type has no such feature.

Anything `apigw` imports from the export but does not enforce yet is listed per route and per
API on the admin `/routes` endpoint, and unevaluated protections fail closed (see
[Fail-closed behavior](#fail-closed-behavior)). How the gap is measured is described in
[Measuring parity](#measuring-parity).

## Routing and requests

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Resource paths, `{param}`, greedy `{proxy+}`, `ANY` | Supported | Supported | Routed per method, then `ANY` |
| `$default` route | n/a | Supported | Used when no other route matches |
| Route-selection specificity | Supported | Supported | REST routes by resource (`matchit`: static, then `{param}`, then greedy; a path with no method answers `403 Missing Authentication Token`). HTTP APIs select the most specific route that matches the path and the method: a full match (static before `{param}`), then a greedy `{proxy+}` match (longer prefix first), then `$default`; a route without the request's method is skipped for a less specific one that has it, and an exact method beats `ANY` on the same path |
| Stage prefix | Supported | Supported | `--base-path /stage` serves routes as an `execute-api` URL does |
| Unknown route | Supported | Supported | REST `403 Missing Authentication Token`, HTTP `404 Not Found` |
| Request ID header | Supported | Supported | `x-amzn-requestid` (REST), `apigw-requestid` (HTTP); REST error responses also carry `x-amz-apigw-id` and `x-amzn-ErrorType` |
| Stage variables | Supported | Supported | Substituted into integration URIs and sent in Lambda events; overridable with `--stage-variable` |
| Request and URL size limits | Supported | Supported | 10 MB body cap answers `413`. REST: URL over 10,240 characters answers `414` and headers over 20,480 bytes `431`; HTTP: request line plus headers over 10,240 bytes answers `431`. The documentation gives the quotas but not the status codes; `414`/`431` are the codes HTTP defines for them. Header text is measured as `name: value` plus CRLF |
| Header handling (`X-Amzn-Remapped-*`, dropped headers, `X-HTTP-Method-Override`, `;` in query strings, HTTP API `Forwarded`) | Supported | Supported | REST follows the documented header table for `HTTP_PROXY` and Lambda (request headers dropped, response headers dropped or renamed to `X-Amzn-Remapped-*`; `Connection` is dropped from backend requests although API Gateway passes it), honors `X-HTTP-Method-Override`, splits query strings on `;`, and adds `x-amzn-apigateway-api-id`, `User-Agent: AmazonAPIGateway_{api-id}` (when absent), `X-Forwarded-Proto`, and `X-Forwarded-Port` to `HTTP_PROXY` requests. HTTP APIs translate `X-Forwarded-*` into `Forwarded` (without `by`, the egress address) and add `Content-Type: application/octet-stream` to body-less requests (the documentation does not name the type) |
| Binary media types and `contentHandling` | Partial | n/a | `binaryMediaTypes` entries (exact, `type/*`, `*/*`, parameters ignored) decide how REST Lambda proxy events carry bodies (base64 when the request `Content-Type` matches, UTF-8 text otherwise) and whether a function's base64 response is decoded (only when the first `Accept` media type matches; without `Accept` the response `Content-Type` decides). `HTTP_PROXY` bodies pass through untouched. `contentHandling` does nothing on proxy integrations, as in API Gateway; on `HTTP`, `AWS`, and `MOCK` integrations it is reported until mapping templates land ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26), [#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27)). HTTP APIs keep base64-encoding bodies that are not valid UTF-8 |
| Response compression, request decompression | Supported | n/a | REST `minimumCompressionSize`: buffered responses at least that large are compressed with the client's highest-weighted `Accept-Encoding` coding (`gzip`, `deflate`; none when that coding is `identity` or one API Gateway does not support); streamed responses never are. Request bodies with `Content-Encoding: gzip` or `deflate` are always decompressed (up to 10 MB), and invalid data answers `400`. Compressing is done in memory, so a response over 10 MB fails with `502` when compression is on |
| Gateway responses (defaults and customization) | Partial | Supported | REST: every response type has API Gateway's default status and message and applies the API's customizations (status, `gatewayresponse.header.*`, body templates with `$context`/`$stageVariables`/`$method.request.*` substitution, `DEFAULT_4XX`/`DEFAULT_5XX` fallback; the 413 is not customizable). Default messages for some 500-class types are not yet checked against recorded AWS responses. HTTP APIs have fixed messages |
| CORS | Supported | Partial | REST CORS is a `MOCK` `OPTIONS` method and works as one. HTTP APIs answer preflights (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) with `204` from the CORS configuration without calling the integration, after the route's own checks (so a preflight to a protected route is refused); an `OPTIONS` request to a path with no route is answered too. Allowed origins get `Access-Control-Allow-*`, `Expose-Headers`, and `Max-Age`; CORS headers from the backend are dropped. The exact headers AWS sends for a disallowed origin and `Vary` are not yet checked against recordings |
| Custom domains and API mappings | Partial | Partial | `--domain-name` serves every API mapped to a domain: API mappings with multi-level keys and routing rules (`routingMode`), the matched prefix stripped, reserved `/ping` and `/sping`, a certificate per domain by SNI. Unmapped requests answer `403 Forbidden`; the exact response API Gateway gives for each failure mode is not verified ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| Mutual TLS, `$context.identity.clientCert` | Partial | Partial | Custom domains with a truststore (read from S3) require a client certificate chained to it, unexpired, in the handshake; `clientCert` is available in access logs and Lambda events. A failed handshake closes the connection instead of answering 403; the chain length limit of four is not enforced; revocation is not checked, as on API Gateway ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| Client address | Supported | Supported | `--trusted-proxies`, PROXY protocol v2, and `X-Forwarded-Client-Cert` from trusted proxies; sent as `sourceIp` and `X-Forwarded-For` |

## Integrations

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| `HTTP_PROXY` | Supported | Supported | Forwards method, headers, body, and query string; path, query, and header mappings from method request parameters and literals; `timeoutInMillis`, bounded as API Gateway bounds it (50 ms minimum; REST has no 29 s cap, HTTP APIs cap at 30 s); streams the response; `tlsConfig` (`insecureSkipVerification` accepts any certificate, `serverNameToVerify` is the name verified and sent as SNI). Mappings from `method.request.*`, `context.*`, `stageVariables.*`, and literals work; other sources are ignored with a warning ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26)) |
| HTTP API parameter mapping (`overwrite:`, `append:`, `remove:`, response mapping) | n/a | Partial | `HTTP_PROXY` integrations: header, query string, and path mappings from `$request.*` (header, querystring, path, path parameters, simple JSON paths in the body), `$context.*`, `$stageVariables.*`, and static values, with `${...}` interpolation; response mappings by backend status code (headers and `overwrite:statuscode`) reading `$response.header.*` and `$response.body.*`. Reserved headers are refused as in API Gateway. Body paths support keys and array indexes only (no recursive descent or filters); mappings on other integration types are ignored |
| HTTP API request validation | n/a | Supported | HTTP APIs have no request validators; one named in a hand-written definition is ignored |
| `AWS_PROXY` Lambda, payload 1.0 and 2.0 | Supported | Partial | Events and responses follow the published formats: `requestContext` (`accountId` from the function ARN, `extendedRequestId`, `resourceId`, full `identity` nulls, `protocol`), `multiValueHeaders` merged with `headers`, cookies, base64 bodies, 2.0 response inference, and the client's header case for REST payload 1.0 (recovered from HTTP/1 request heads; HTTP/2 clients get lower case). Region from the function ARN, qualified ARNs and aliases, assumed integration roles, per-function endpoints (`--lambda-endpoint`), timeouts, and Lambda's 6 MB request/response limit (`502`). HTTP API `http.protocol` reports the client's version, which is not documented; `identity.clientCert` is reported for mutual TLS clients ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| `MOCK` | Partial | n/a | Status from the request template's `statusCode`, literal response headers, and the response template, returned verbatim ([#23](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/23), [#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27)) |
| `HTTP` (non-proxy) | Planned | n/a | `501`, reason on `/routes` ([#28](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/28)) |
| `AWS` service integrations and non-proxy Lambda | Planned | n/a | `501` ([#29](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/29)) |
| HTTP API integration subtypes (SQS, EventBridge, Step Functions, Kinesis, AppConfig) | n/a | Planned | `501` ([#30](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/30)) |
| VPC links and private integrations | Partial | Partial | `HTTP_PROXY` integrations with `--vpc-link CONNECTION_ID=URL` are served from that in-cluster URL (REST: the URI's host as the `Host` header; HTTP: the request path after the URL, with the stage prefix); a link with no mapping answers `501` with the reason on `/routes`. Load balancer and Cloud Map resolution is not attempted because those addresses are private to the VPC. No recorded fixture covers a VPC link yet |
| Response streaming (`responseTransferMode: STREAM`) | Supported | n/a | Lambda through `InvokeWithResponseStream` (`/response-streaming-invocations` URIs; metadata, 8 null bytes, payload) and `HTTP_PROXY`; 15 minute limit, 5 minute idle limit, `$context.integration.responseTransferMode` and `timeToAllHeaders`. Output that breaks the format answers `500`. Through `--lambda-endpoint` the emulator's HTTP body is streamed; function errors in HTTP trailers are not read |
| Integration credentials roles | Supported | Supported | Lambda routes assume the integration's `credentials` role, or use the gateway's own credentials with `--integration-credentials=gateway`; the role's trust policy must allow the gateway (see [deployment](deployment.md)) |
| Caller-credential passthrough (`arn:aws:iam::*:user/*`) | Not possible | Not possible | Needs IAM-authenticated callers; the route is not served (`501`) |
| AWS-generated backend client certificates | Out of scope | n/a | Supply your own certificate to the backend |
| Local integration overrides | Supported | Supported | `--integration-overrides` re-points routes; not an API Gateway feature |

## Mapping templates

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Velocity (VTL) engine: directives, Java value model, limits | Partial | n/a | The `apigw-vtl` crate parses and renders Velocity 1.7 templates (references, `#set`, `#if`, `#foreach` with the 1,000-iteration cap, `#break`, `#stop`, comments, whitespace gobbling, Java `toString` and arithmetic, `String`/`List`/`Map` methods) with output, step, and depth limits, checked against Apache Velocity 1.7. It is not yet called by the request pipeline, so integration templates are still not rendered ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26), [#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27)). `#macro`, `#parse`, `#include`, `#evaluate`, and `#define` are rejected; integers beyond 64 bits are an error where Java promotes to `BigInteger`; `Map` keys are strings ([#23](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/23)) |
| `$input`, `$util`, `$context`, `$stageVariables` | Partial | n/a | Implemented in `apigw-vtl`: `$input.body`, `json()`, `path()` (Jayway JsonPath 2.x: filters, slices, wildcards, deep scan, functions on definite and wildcard paths), `params()`, `$util` escaping, URL and Base64 helpers and `parseJson`, a caller-owned `$context` including `requestOverride` and `responseOverride`, and `$stageVariables`. Not yet wired into the pipeline; JSON path functions after `..` are rejected ([#24](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/24)) |
| Java regular expressions (selection patterns, identity validation, `split`) | Partial | n/a | The `apigw-regex` crate translates `java.util.regex` to `fancy-regex` with Java's whole-string `matches`, ASCII classes, line terminators, replacement strings, and `split`, checked against real Java; identity validation expressions use it. Not yet used for selection patterns or templates ([#22](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/22)) |
| Template output checked against a Velocity/Jayway oracle | Partial | n/a | `tools/vtl-oracle` renders about 9,500 templates with Apache Velocity 1.7 and Jayway JsonPath 2.9 in a pinned JDK image (operator matrix, whitespace matrix, random templates, JSON paths, hand-written gateway templates), and `apigw-vtl`'s `oracle` test compares output and `$context` for each; a weekly workflow re-renders the corpus, replays fresh random templates, and fuzzes. Four random cases still differ (Velocity's lexer state after a property reference and a directive). The oracle stubs AWS's `$input`/`$util`/`$context` wrappers, so those details await `TestInvokeMethod` against a deployed reference stack ([#25](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/25)) |
| Integration request: all `requestParameters` sources, templates by content type, `passthroughBehavior`, `contentHandling` | Planned | n/a | ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26)) |
| Integration response: `selectionPattern`, parameters, templates, method responses | Planned | n/a | ([#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27)) |

## Authorization and access control

Routes whose protection is not evaluated yet are refused, never served unprotected.

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Lambda authorizers (TOKEN, REQUEST) | Supported | Supported | REST `TOKEN` (with `identityValidationExpression`) and `REQUEST`; HTTP `REQUEST` with payload 1.0 and 2.0 and simple responses. Identity sources, result caching by identity sources and TTL (REST default 300 s, HTTP off), and the returned policy re-evaluated against each method ARN, cached or not. `401` for a missing identity source or a function that fails with `Unauthorized`, `403` for a denying policy, `500` for any other failure or an invalid response, and `10 s` timeout. `authorizerCredentials` roles are assumed. Differences: the method ARN's partition, region, and account come from the authorizer function's ARN; the validation expression runs through the Java regex translator, and an authorizer whose expression it cannot translate is refused with `401`; results are cached in the state backend, which is per replica until a shared backend is configured, under a hash of the identity sources; `500` bodies use the default gateway response messages ([#31](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/31) REST, [#34](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/34) HTTP) |
| Cognito user pool authorizers | Supported | n/a | The token's signature is verified against the pool's published keys (fetched from `{issuer}/.well-known/jwks.json`, cached for 2 hours, refreshed when a token names an unknown key), `exp`/`nbf`/`iat` are checked, and the issuer must be one of the authorizer's pools. A route without scopes needs an ID token, a route with scopes an access token carrying one of them (`401` otherwise); an optional `identityValidationExpression` is matched against `aud`. Claims reach `$context.authorizer.claims` as strings (lists comma-joined, `exp` and `iat` as dates). The token may carry a `Bearer ` prefix ([#32](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/32)) |
| JWT authorizers | n/a | Supported | RS256/RS384/RS512 tokens verified against the issuer's OIDC discovery document and key set (1.5 s timeout and 150 KB cap per fetch, keys cached 2 hours, at most one refresh per issuer every 30 s). `iss`, `aud` (or `client_id` when there is no `aud`), `exp`, `nbf`, and `iat` are checked; a route's scopes need one of them in `scope` or `scp` (`403` when missing, `401` for any other failure). Claims reach `$context.authorizer.claims` and `.scopes`, and `requestContext.authorizer.jwt` in payload 2.0 events. Differences: an authorizer with no audience or an `http` issuer is refused with `401`, RSA-PSS is not accepted, and `401` answers carry no `WWW-Authenticate` header ([#33](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/33)) |
| API keys and usage plans (keys, quotas, plan throttles) | Supported | n/a | A method that requires a key admits an enabled key that belongs to a usage plan of the stage; otherwise `403 Forbidden` (`INVALID_API_KEY`). Key source `HEADER` (`x-api-key`) or `AUTHORIZER` (`usageIdentifierKey`). The plan's default and per-method throttles (most specific wins: `/path/METHOD`, then `*/*`, then the plan) answer `429 Too Many Requests` and its day, week, or month quota (UTC calendar periods, week from Monday) `429 Limit Exceeded` (`QUOTA_EXCEEDED`); a throttled request does not use up quota. Keys, plans, and associations are read live every `--usage-refresh-seconds` (60) with paced, paginated reads, and kept only as SHA-256 hashes; data older than an hour is not trusted. Differences: a key disabled in API Gateway keeps working until the next read; quota `offset` is not applied; with the in-memory state backend each replica counts its share of every limit, while `--valkey-url` counts exactly across replicas (if Valkey is unreachable, requests are admitted); a plan with a limit this gateway cannot read is dropped, so its keys are refused; HTTP APIs and `--openapi-file` sources cannot read keys, so key routes answer `403` ([#35](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/35)) |
| Request validators and models | Supported | n/a | Required query string and header parameters must be present and not blank (`400` `BAD_REQUEST_PARAMETERS`, message `Missing required request parameters: [a, b]`); bodies are validated against the model of the request's content type (else `$default`, else not validated) with JSON Schema draft 4, `$ref`s into `#/components/schemas/...` resolved against the API's models and nothing fetched from outside (`400` `BAD_REQUEST_BODY`, message `Invalid request body`). Parameters are checked before the body, both before throttling and the integration. Never skipped by `--insecure-skip-authorization`. See [Request validation](#request-validation) ([#36](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/36)) |
| Resource policies | Supported | n/a | Two-phase evaluation as in AWS's authorization-flow tables: an explicit `Deny` is checked before authentication; afterwards the policy is combined with a Lambda authorizer (an `Allow` from either suffices) or a Cognito user pool (both must allow), and alone when the route has no authorizer (an explicit `Allow` is required). Callers are anonymous (a `SigV4` signature cannot be verified), so only principals naming `*` apply. Conditions evaluated: `aws:SourceIp` (`IpAddress`/`NotIpAddress`, from the trusted client address), `aws:UserAgent`, `aws:Referer`, `aws:SecureTransport`, `aws:CurrentTime`/`aws:EpochTime`, with the string and date operators; any other condition, a qualifier, a policy variable, or a client address that could not be established counts as matching for a `Deny` and not matching for an `Allow`. `--insecure-skip-authorization` takes the authorizer to have allowed the caller but never skips the policy. A policy that cannot be read refuses every route with `403`. Denials answer `403` with AWS's message (`User: anonymous is not authorized to perform: execute-api:Invoke on resource: ... with an explicit deny in a resource-based policy` or `... because no resource-based policy allows the execute-api:Invoke action`), the account masked to its last four digits and taken from the ARNs in the policy ([#37](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/37)) |
| `AWS_IAM` authorization | Not possible | Not possible | A caller's SigV4 signature cannot be verified without their secret key. REST answers `403 Missing Authentication Token` and HTTP `403 Forbidden`, as API Gateway does for unsigned requests; `--insecure-skip-authorization` serves the route without a check |
| AWS WAF | Out of scope | n/a | Put a WAF or equivalent in front of the gateway |

## Throttling, caching, and releases

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Stage, method, and route throttling (`429`) | Partial | Partial | Token buckets per method (REST `methodSettings`, `*/*` default) and per route (HTTP route settings, default route settings); `429` through the `THROTTLED` gateway response (REST) or `{"message":"Too Many Requests"}` (HTTP). Account-level and usage-plan throttles are not applied; limits are per replica (see below) |
| Shared limiter state across replicas | Partial | Partial | In-memory per replica; `--replicas N` divides throttle rates and bursts by `N`, so the API-wide rate is approximately the configured one (a replica's bucket holds at least one token, so with more replicas than burst tokens the API-wide burst is larger). An optional Valkey backend that makes limits exact is planned ([#35](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/35)) |
| Response caching | Partial | n/a | Method caching with TTL, cache key parameters, the 1 MB entry cap, and `Cache-Control: max-age=0` handling per `requireAuthorizationForCacheControl` and the unauthorized strategy, in the state backend (per replica until a shared backend exists). Differences: only 2xx responses are cached; a client is never authorized to invalidate, so authorization-required methods treat every `max-age=0` as unauthorized; cache encryption and cluster size do not apply; the exact `403` body for `FAIL_WITH_403` is the `ACCESS_DENIED` default ([#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38)) |
| Canary releases | Partial | n/a | Traffic is split by `percentTraffic` with the canary's stage variable overrides, `$context.isCanaryRequest`, and separate canary logs and metrics. The canary's structure comes from `--canary-export-stage` (a stage holding the canary deployment); without it only stage variables differ. `useStageCache` controls whether the canary uses the response cache ([#39](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/39)) |

## Observability

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Access logs to CloudWatch Logs or Firehose | Supported | Supported | The stage's `$context` format is rendered per request and written to the stage's log group (one stream per process) or Firehose stream, standard output otherwise. `$context.responseLength` is `-` for streamed responses of unknown length; variables for features not implemented yet render `-` ([#41](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/41)) |
| CloudWatch metrics | Partial | Partial | Published as embedded metric format events under `--metrics-namespace` (not `AWS/ApiGateway`), aggregated per minute, with API Gateway's metric names and dimensions. Use `Sum` for `Count` and error metrics; latency percentiles are estimated from at most 100 samples per minute. Cache hit and miss counts for cached routes, no `DataProcessed` ([#42](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/42)) |
| X-Ray tracing | Partial | n/a | REST stages with tracing send one segment per sampled request and pass `X-Amzn-Trace-Id` (and `traceparent` to HTTP backends) downstream; callers' sampling decisions are honored, otherwise X-Ray's default rule (1 per second, then 5%) is used without fetching sampling rules. No integration subsegment, no passive mode ([#43](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/43)) |
| Execution logs | Partial | n/a | `loggingLevel` and `dataTraceEnabled` write a request trace to `API-Gateway-Execution-Logs_{apiId}/{stage}`; steps this gateway does not perform are not logged and bodies are not logged ([#44](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/44)) |

## Operating the gateway

These are properties of `apigw`, not API Gateway features, and are all supported:

| Capability | Behavior |
|---|---|
| Definition source | `GetExport` (REST) or `ExportApi` (HTTP) for the deployed stage, or an export file; `GetStage` is checked each refresh and the export is re-downloaded only when the deployment changed |
| Live refresh | The router is swapped without dropping requests; a failed refresh keeps the current routes and backs off with jitter |
| Last-known-good cache | `--config-cache` starts the gateway when API Gateway is unreachable |
| TLS | Always on; certificates reload when the files change |
| Admin endpoints | `/healthz` and `/routes` (also TLS) |

## Out of scope

| Feature | Why |
|---|---|
| WebSocket APIs | A different protocol and control plane |
| Private and edge-optimized endpoint types | The gateway serves any API's export as one endpoint; the endpoint type has no effect |
| SDK generation, API documentation parts, developer portals | Control-plane features, not request handling |

## Fail-closed behavior

| Situation | Response |
|---|---|
| Authorizer, API key, or IAM requirement on the route | `401`, `403 Forbidden`, or `403 Missing Authentication Token` as in [Authorization](#authorization-and-access-control) |
| Resource policy on the API that cannot be read | `403` on every route |
| Request validator whose model cannot be compiled | `501` |
| Integration the gateway cannot execute | `501 Integration not supported by this gateway`, with the reason on `/routes` |

## Measuring parity

`crates/apigw-parity` records the behavior of real API Gateway APIs deployed from
[`terraform/environments/dev`](../terraform/README.md) and replays the same requests against `apigw`
in CI, so a status here is backed by a fixture. Cases for features `apigw` lacks carry a
`known_gap` issue marker, which keeps this matrix and the fixtures in step: when a gap closes,
the case must lose its marker and the row changes status. See [parity/README.md](../parity/README.md).

Imported settings that are not enforced yet map to issues as follows:

| `/routes` feature | Issue |
|---|---|
| `content_handling` (on `HTTP`, `AWS`, and `MOCK` integrations) | [#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26), [#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27) |

## Fidelity limits of the export

- REST control-plane reads (`GetResources`, `GetAuthorizers`, ...) return the draft, not the
  deployment. Only `GetExport` for a stage and HTTP `ExportApi` with a stage name reflect what
  is deployed, so the export is the structural source and usage plans, API keys, and domain
  mappings are read live.
- A canary deployment cannot be exported. The canary release is built from the stage's export
  unless `--canary-export-stage` supplies a stage that holds the canary deployment.
- Control-plane calls share a 10 requests per second per-account limit, so refreshes are
  conditional and jittered.

## Request validation

Differences from API Gateway's validators:

- `$context.error.validationErrorString` carries this gateway's schema violation messages (for
  example `["name" is a required property]`), not API Gateway's wording, and is limited to ten
  violations and 1,024 characters. The default `BAD_REQUEST_BODY` response does not include it.
- `pattern` uses Rust regular expression syntax rather than Java's, and `format` is not enforced.
- An empty body, malformed JSON, and a body that is not valid JSON are all `Invalid request body`
  when a model applies to the request's content type; a request without `Content-Type` is treated as
  `application/json`.
- A `$ref` that is not a model of the API (a missing model, or an external URL or file) makes the
  route answer `501` instead of being fetched; `/routes` gives the reason.
- Parameters are matched by name as declared: header names ignore case, query names do not. Path
  parameters are always present on a matched route, and a cookie parameter is not checked.
