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
| Request and URL size limits | Partial | Partial | 10 MB body cap answers `413`; the REST URL/header and HTTP request-line limits are not enforced ([#17](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/17)) |
| Header handling (`X-Amzn-Remapped-*`, dropped headers, `X-HTTP-Method-Override`, `;` in query strings, HTTP API `Forwarded`) | Planned | Planned | Hop-by-hop headers are dropped and `X-Forwarded-For` is rewritten from the client address ([#16](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/16)) |
| Binary media types and `contentHandling` | Planned | n/a | Lambda bodies are decoded by `isBase64Encoded` only; the setting is imported and reported ([#18](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/18)) |
| Response compression, request decompression | Planned | n/a | Imported and reported ([#18](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/18)) |
| Gateway responses (defaults and customization) | Partial | Supported | REST: every response type has API Gateway's default status and message and applies the API's customizations (status, `gatewayresponse.header.*`, body templates with `$context`/`$stageVariables`/`$method.request.*` substitution, `DEFAULT_4XX`/`DEFAULT_5XX` fallback; the 413 is not customizable). Default messages for some 500-class types are not yet checked against recorded AWS responses. HTTP APIs have fixed messages |
| CORS | Supported | Partial | REST CORS is a `MOCK` `OPTIONS` method and works as one. HTTP APIs answer preflights (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) with `204` from the CORS configuration without calling the integration, after the route's own checks (so a preflight to a protected route is refused); an `OPTIONS` request to a path with no route is answered too. Allowed origins get `Access-Control-Allow-*`, `Expose-Headers`, and `Max-Age`; CORS headers from the backend are dropped. The exact headers AWS sends for a disallowed origin and `Vary` are not yet checked against recordings |
| Custom domains and API mappings | Partial | Partial | `--domain-name` serves every API mapped to a domain: API mappings with multi-level keys and routing rules (`routingMode`), the matched prefix stripped, reserved `/ping` and `/sping`, a certificate per domain by SNI. Unmapped requests answer `403 Forbidden`; the exact response API Gateway gives for each failure mode is not verified ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| Mutual TLS, `$context.identity.clientCert` | Planned | Planned | TLS is always on; client certificates are not requested ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| Client address | Supported | Supported | `--trusted-proxies`, PROXY protocol v2, and `X-Forwarded-Client-Cert` from trusted proxies; sent as `sourceIp` and `X-Forwarded-For` |

## Integrations

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| `HTTP_PROXY` | Partial | Partial | Forwards method, headers, body, and query string; path, query, and header mappings from method request parameters and literals; `timeoutInMillis`; streams the response. Mappings from `method.request.*`, `context.*`, `stageVariables.*`, and literals work; other sources are ignored with a warning ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26)); `tlsConfig` is not applied ([#16](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/16)) |
| HTTP API parameter mapping (`overwrite:`, `append:`, `remove:`, response mapping) | n/a | Partial | `HTTP_PROXY` integrations: header, query string, and path mappings from `$request.*` (header, querystring, path, path parameters, simple JSON paths in the body), `$context.*`, `$stageVariables.*`, and static values, with `${...}` interpolation; response mappings by backend status code (headers and `overwrite:statuscode`) reading `$response.header.*` and `$response.body.*`. Reserved headers are refused as in API Gateway. Body paths support keys and array indexes only (no recursive descent or filters); mappings on other integration types are ignored |
| HTTP API request validation | n/a | Supported | HTTP APIs have no request validators; one named in a hand-written definition is ignored |
| `AWS_PROXY` Lambda, payload 1.0 and 2.0 | Supported | Partial | Events and responses follow the published formats: `requestContext` (`accountId` from the function ARN, `extendedRequestId`, `resourceId`, full `identity` nulls, `protocol`), `multiValueHeaders` merged with `headers`, cookies, base64 bodies, 2.0 response inference, and the client's header case for REST payload 1.0 (recovered from HTTP/1 request heads; HTTP/2 clients get lower case). Region from the function ARN, qualified ARNs and aliases, assumed integration roles, per-function endpoints (`--lambda-endpoint`), timeouts, and Lambda's 6 MB request/response limit (`502`). HTTP API `http.protocol` reports the client's version, which is not documented; `identity.clientCert` waits for mutual TLS ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| `MOCK` | Partial | n/a | Status from the request template's `statusCode`, literal response headers, and the response template, returned verbatim ([#23](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/23), [#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27)) |
| `HTTP` (non-proxy) | Planned | n/a | `501`, reason on `/routes` ([#28](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/28)) |
| `AWS` service integrations and non-proxy Lambda | Planned | n/a | `501` ([#29](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/29)) |
| HTTP API integration subtypes (SQS, EventBridge, Step Functions, Kinesis, AppConfig) | n/a | Planned | `501` ([#30](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/30)) |
| VPC links and private integrations | Planned | Planned | `501` until a connection ID can be mapped to an in-cluster URL ([#20](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/20)) |
| Response streaming (`responseTransferMode: STREAM`) | Supported | n/a | Lambda through `InvokeWithResponseStream` (`/response-streaming-invocations` URIs; metadata, 8 null bytes, payload) and `HTTP_PROXY`; 15 minute limit, 5 minute idle limit, `$context.integration.responseTransferMode` and `timeToAllHeaders`. Output that breaks the format answers `500`. Through `--lambda-endpoint` the emulator's HTTP body is streamed; function errors in HTTP trailers are not read |
| Integration credentials roles | Supported | Supported | Lambda routes assume the integration's `credentials` role, or use the gateway's own credentials with `--integration-credentials=gateway`; the role's trust policy must allow the gateway (see [deployment](deployment.md)) |
| Caller-credential passthrough (`arn:aws:iam::*:user/*`) | Not possible | Not possible | Needs IAM-authenticated callers; the route is not served (`501`) |
| AWS-generated backend client certificates | Out of scope | n/a | Supply your own certificate to the backend |
| Local integration overrides | Supported | Supported | `--integration-overrides` re-points routes; not an API Gateway feature |

## Mapping templates

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Velocity (VTL) engine: directives, Java value model, limits | Planned | n/a | Templates are not rendered ([#23](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/23)) |
| `$input`, `$util`, `$context`, `$stageVariables` | Planned | n/a | ([#24](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/24)) |
| Java regular expressions (selection patterns, identity validation, `split`) | Planned | n/a | Patterns are not evaluated ([#22](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/22)) |
| Template output checked against a Velocity/Jayway oracle | Planned | n/a | ([#25](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/25)) |
| Integration request: all `requestParameters` sources, templates by content type, `passthroughBehavior`, `contentHandling` | Planned | n/a | ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26)) |
| Integration response: `selectionPattern`, parameters, templates, method responses | Planned | n/a | ([#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27)) |

## Authorization and access control

Routes whose protection is not evaluated yet are refused, never served unprotected.

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Lambda authorizers (TOKEN, REQUEST) | Supported | Supported | REST `TOKEN` (with `identityValidationExpression`) and `REQUEST`; HTTP `REQUEST` with payload 1.0 and 2.0 and simple responses. Identity sources, result caching by identity sources and TTL (REST default 300 s, HTTP off), and the returned policy re-evaluated against each method ARN, cached or not. `401` for a missing identity source or a function that fails with `Unauthorized`, `403` for a denying policy, `500` for any other failure or an invalid response, and `10 s` timeout. `authorizerCredentials` roles are assumed. Differences: the method ARN's partition, region, and account come from the authorizer function's ARN; the validation expression runs through the Java regex translator, and an authorizer whose expression it cannot translate is refused with `401`; results are cached in the state backend, which is per replica until a shared backend is configured, under a hash of the identity sources; `500` bodies use the default gateway response messages ([#31](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/31) REST, [#34](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/34) HTTP) |
| Cognito user pool authorizers | Supported | n/a | The token's signature is verified against the pool's published keys (fetched from `{issuer}/.well-known/jwks.json`, cached for 2 hours, refreshed when a token names an unknown key), `exp`/`nbf`/`iat` are checked, and the issuer must be one of the authorizer's pools. A route without scopes needs an ID token, a route with scopes an access token carrying one of them (`401` otherwise); an optional `identityValidationExpression` is matched against `aud`. Claims reach `$context.authorizer.claims` as strings (lists comma-joined, `exp` and `iat` as dates). The token may carry a `Bearer ` prefix ([#32](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/32)) |
| JWT authorizers | n/a | Supported | RS256/RS384/RS512 tokens verified against the issuer's OIDC discovery document and key set (1.5 s timeout and 150 KB cap per fetch, keys cached 2 hours, at most one refresh per issuer every 30 s). `iss`, `aud` (or `client_id` when there is no `aud`), `exp`, `nbf`, and `iat` are checked; a route's scopes need one of them in `scope` or `scp` (`403` when missing, `401` for any other failure). Claims reach `$context.authorizer.claims` and `.scopes`, and `requestContext.authorizer.jwt` in payload 2.0 events. Differences: an authorizer with no audience or an `http` issuer is refused with `401`, RSA-PSS is not accepted, and `401` answers carry no `WWW-Authenticate` header ([#33](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/33)) |
| API keys and usage plans (keys, quotas, plan throttles) | Planned | n/a | `403 Forbidden` on routes that require a key ([#35](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/35)) |
| Request validators and models | Planned | n/a | `501` on validated routes; `--unsupported-validation=ignore` forwards unvalidated requests ([#36](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/36)) |
| Resource policies | Planned | n/a | `403` on every route of an API with a policy; `--unsupported-resource-policy=ignore` serves them unrestricted ([#37](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/37)) |
| `AWS_IAM` authorization | Not possible | Not possible | A caller's SigV4 signature cannot be verified without their secret key. REST answers `403 Missing Authentication Token` and HTTP `403 Forbidden`, as API Gateway does for unsigned requests; `--insecure-skip-authorization` serves the route without a check |
| AWS WAF | Out of scope | n/a | Put a WAF or equivalent in front of the gateway |

## Throttling, caching, and releases

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Stage, method, and route throttling (`429`) | Partial | Partial | Token buckets per method (REST `methodSettings`, `*/*` default) and per route (HTTP route settings, default route settings); `429` through the `THROTTLED` gateway response (REST) or `{"message":"Too Many Requests"}` (HTTP). Account-level and usage-plan throttles are not applied; limits are per replica (see below) |
| Shared limiter state across replicas | Partial | Partial | In-memory per replica; `--replicas N` divides throttle rates and bursts by `N`, so the API-wide rate is approximately the configured one (a replica's bucket holds at least one token, so with more replicas than burst tokens the API-wide burst is larger). An optional Valkey backend that makes limits exact is planned ([#35](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/35)) |
| Response caching | Planned | n/a | Cache settings and key parameters are imported and reported ([#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38)) |
| Canary releases | Partial | n/a | Traffic is split by `percentTraffic` with the canary's stage variable overrides, `$context.isCanaryRequest`, and separate canary logs and metrics. The canary's structure comes from `--canary-export-stage` (a stage holding the canary deployment); without it only stage variables differ. `useStageCache` waits for [#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38) ([#39](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/39)) |

## Observability

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Access logs to CloudWatch Logs or Firehose | Supported | Supported | The stage's `$context` format is rendered per request and written to the stage's log group (one stream per process) or Firehose stream, standard output otherwise. `$context.responseLength` is `-` for streamed responses of unknown length; variables for features not implemented yet render `-` ([#41](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/41)) |
| CloudWatch metrics | Partial | Partial | Published as embedded metric format events under `--metrics-namespace` (not `AWS/ApiGateway`), aggregated per minute, with API Gateway's metric names and dimensions. Use `Sum` for `Count` and error metrics; latency percentiles are estimated from at most 100 samples per minute. No cache metrics until [#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38), no `DataProcessed` ([#42](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/42)) |
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
| Resource policy on the API | `403` on every route |
| Request validator on the route | `501` |
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
| `binary_media_types`, `compression`, `content_handling` | [#18](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/18) |
| `integration_tls_config` | [#16](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/16) |
| `response_caching` | [#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38) |

## Fidelity limits of the export

- REST control-plane reads (`GetResources`, `GetAuthorizers`, ...) return the draft, not the
  deployment. Only `GetExport` for a stage and HTTP `ExportApi` with a stage name reflect what
  is deployed, so the export is the structural source and usage plans, API keys, and domain
  mappings are read live.
- A canary deployment cannot be exported. The canary release is built from the stage's export
  unless `--canary-export-stage` supplies a stage that holds the canary deployment.
- Control-plane calls share a 10 requests per second per-account limit, so refreshes are
  conditional and jittered.
