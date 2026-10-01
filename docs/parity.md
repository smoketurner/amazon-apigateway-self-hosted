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
| Route-selection specificity | Partial | Partial | Static, then `{param}`, then greedy through `matchit`; not yet verified against every API Gateway tie-break ([#19](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/19)) |
| Stage prefix | Supported | Supported | `--base-path /stage` serves routes as an `execute-api` URL does |
| Unknown route | Supported | Supported | REST `403 Missing Authentication Token`, HTTP `404 Not Found` |
| Request ID header | Supported | Supported | `x-amzn-requestid` (REST), `apigw-requestid` (HTTP); `x-amz-apigw-id` and `x-amzn-ErrorType` follow with [#15](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/15) |
| Stage variables | Supported | Supported | Substituted into integration URIs and sent in Lambda events; overridable with `--stage-variable` |
| Request and URL size limits | Partial | Partial | 10 MB body cap answers `413`; the REST URL/header and HTTP request-line limits are not enforced ([#17](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/17)) |
| Header handling (`X-Amzn-Remapped-*`, dropped headers, `X-HTTP-Method-Override`, `;` in query strings, HTTP API `Forwarded`) | Planned | Planned | Hop-by-hop headers are dropped and `X-Forwarded-For` is rewritten from the client address ([#16](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/16)) |
| Binary media types and `contentHandling` | Planned | n/a | Lambda bodies are decoded by `isBase64Encoded` only; the setting is imported and reported ([#18](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/18)) |
| Response compression, request decompression | Planned | n/a | Imported and reported ([#18](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/18)) |
| Gateway responses (defaults and customization) | Planned | Planned | Errors use API Gateway's stock status and message (HTTP APIs have fixed messages); REST customizations are imported and reported ([#15](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/15)) |
| CORS | Supported | Planned | REST CORS is a `MOCK` `OPTIONS` method and works as one; HTTP API CORS is imported and reported ([#19](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/19)) |
| Custom domains and API mappings | Planned | Planned | Serve behind your own ingress, with `--base-path` for a stage prefix ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| Mutual TLS, `$context.identity.clientCert` | Planned | Planned | TLS is always on; client certificates are not requested ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| Client address | Supported | Supported | `--trusted-proxies`, PROXY protocol v2, and `X-Forwarded-Client-Cert` from trusted proxies; sent as `sourceIp` and `X-Forwarded-For` |

## Integrations

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| `HTTP_PROXY` | Partial | Partial | Forwards method, headers, body, and query string; path, query, and header mappings from method request parameters and literals; `timeoutInMillis`; streams the response. Mappings from `stageVariables.*` and `context.*` are ignored with a warning ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26)); `tlsConfig` is not applied ([#16](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/16)) |
| HTTP API parameter mapping (`overwrite:`, `append:`, `remove:`, response mapping) | n/a | Planned | Imported and reported ([#19](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/19)) |
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
| Lambda authorizers (TOKEN, REQUEST) | Planned | Planned | `401 Unauthorized` unless `--insecure-skip-authorization` ([#31](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/31) REST, [#34](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/34) HTTP) |
| Cognito user pool authorizers | Planned | n/a | `401` ([#32](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/32)) |
| JWT authorizers | n/a | Planned | `401` ([#33](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/33)) |
| API keys and usage plans (keys, quotas, plan throttles) | Planned | n/a | `403 Forbidden` on routes that require a key ([#35](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/35)) |
| Request validators and models | Planned | n/a | `501` on validated routes; `--unsupported-validation=ignore` forwards unvalidated requests ([#36](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/36)) |
| Resource policies | Planned | n/a | `403` on every route of an API with a policy; `--unsupported-resource-policy=ignore` serves them unrestricted ([#37](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/37)) |
| `AWS_IAM` authorization | Not possible | Not possible | A caller's SigV4 signature cannot be verified without their secret key. REST answers `403 Missing Authentication Token` and HTTP `403 Forbidden`, as API Gateway does for unsigned requests; `--insecure-skip-authorization` serves the route without a check |
| AWS WAF | Out of scope | n/a | Put a WAF or equivalent in front of the gateway |

## Throttling, caching, and releases

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Stage, method, and route throttling (`429`) | Planned | Planned | Imported and reported, not enforced ([#21](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/21)) |
| Shared limiter state across replicas | Planned | Planned | In-memory per replica, quotas divided by replica count, with an optional Valkey backend ([#21](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/21), [#35](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/35)) |
| Response caching | Planned | n/a | Cache settings and key parameters are imported and reported ([#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38)) |
| Canary releases | Planned | n/a | The deployed stage is served; the canary split is reported ([#39](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/39)) |

## Observability

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Access logs to CloudWatch Logs or Firehose | Planned | Planned | Gateway logs go to stdout as JSON ([#41](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/41)) |
| CloudWatch metrics | Planned | Planned | ([#42](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/42)) |
| X-Ray tracing | Planned | Planned | A client's `X-Amzn-Trace-Id` is passed to Lambda invocations; no segments are sent ([#43](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/43)) |
| Execution logs | Planned | n/a | ([#44](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/44)) |

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
[`reference/terraform`](../reference/README.md) and replays the same requests against `apigw`
in CI, so a status here is backed by a fixture. Cases for features `apigw` lacks carry a
`known_gap` issue marker, which keeps this matrix and the fixtures in step: when a gap closes,
the case must lose its marker and the row changes status. See [parity/README.md](../parity/README.md).

Imported settings that are not enforced yet map to issues as follows:

| `/routes` feature | Issue |
|---|---|
| `gateway_responses` | [#15](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/15) |
| `binary_media_types`, `compression`, `content_handling` | [#18](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/18) |
| `cors`, `parameter_mapping` | [#19](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/19) |
| `integration_tls_config` | [#16](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/16) |
| `throttling` | [#21](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/21) |
| `response_caching` | [#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38) |
| `canary` | [#39](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/39) |
| `access_logs` | [#41](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/41) |
| `detailed_metrics` | [#42](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/42) |
| `tracing` | [#43](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/43) |
| `execution_logs` | [#44](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/44) |

## Fidelity limits of the export

- REST control-plane reads (`GetResources`, `GetAuthorizers`, ...) return the draft, not the
  deployment. Only `GetExport` for a stage and HTTP `ExportApi` with a stage name reflect what
  is deployed, so the export is the structural source and usage plans, API keys, and domain
  mappings are read live.
- A canary deployment cannot be exported; only the stage's main deployment is served until
  [#39](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/39).
- Control-plane calls share a 10 requests per second per-account limit, so refreshes are
  conditional and jittered.
