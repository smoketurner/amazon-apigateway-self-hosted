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
| Header handling (`X-Amzn-Remapped-*`, dropped headers, `X-HTTP-Method-Override`, `;` in query strings, HTTP API `Forwarded`) | Supported | Supported | REST follows the documented header table for `HTTP_PROXY` and Lambda (request headers dropped, response headers dropped or renamed to `X-Amzn-Remapped-*`; `Connection` is dropped from backend requests although API Gateway passes it), honors `X-HTTP-Method-Override`, splits query strings on `;`, and adds `x-amzn-apigateway-api-id`, `User-Agent: AmazonAPIGateway_{api-id}` (when absent), `X-Forwarded-Proto`, and `X-Forwarded-Port` to `HTTP_PROXY` requests. HTTP APIs translate `X-Forwarded-*` into `Forwarded` (without `by`, the egress address), set `Via: HTTP/1.1 AmazonAPIGateway`, send `Content-Length: 0` with body-less requests, and call a request that names no type `application/x-www-form-urlencoded` unless it is a `GET` |
| Binary media types and `contentHandling` | Supported | n/a | `binaryMediaTypes` entries (exact, `type/*`, `*/*`, parameters ignored) decide how REST Lambda proxy events carry bodies (base64 when the request `Content-Type` matches, UTF-8 text otherwise) and whether a function's base64 response is decoded (only when the first `Accept` media type matches; without `Accept` the response `Content-Type` decides). `HTTP_PROXY` bodies pass through untouched. `contentHandling` does nothing on proxy integrations, as in API Gateway; on `HTTP`, `AWS`, and `MOCK` integrations it converts payloads as described under [Mapping templates](#mapping-templates). HTTP APIs base64-encode every body whose `Content-Type` is not one API Gateway takes for text (see [Measured against deployed APIs](#measured-against-deployed-apis)) |
| Response compression, request decompression | Supported | n/a | REST `minimumCompressionSize`: buffered responses at least that large are compressed with the client's highest-weighted `Accept-Encoding` coding (`gzip`, `deflate`; none when that coding is `identity` or one API Gateway does not support); streamed responses never are. Request bodies with `Content-Encoding: gzip` or `deflate` are always decompressed (up to 10 MB), and invalid data answers `400`. Compressing is done in memory, so a response over 10 MB fails with `502` when compression is on |
| Gateway responses (defaults and customization) | Supported | Supported | REST: every response type has API Gateway's default status and message and applies the API's customizations (status, `gatewayresponse.header.*`, body templates with `$context`/`$stageVariables`/`$method.request.*` substitution, `DEFAULT_4XX`/`DEFAULT_5XX` fallback; the 413 is not customizable). An authorizer the gateway cannot use leaves `$context.error.message` and `messageString` null (`{"message":null}`), and an integration host that does not resolve, including one built from an unset stage variable, is a `500` `API_CONFIGURATION_ERROR` named `InternalServerErrorException` (`rest-token-authorizer-malformed`, `rest-http-proxy-unresolvable-host`); an HTTP API answers that host with `500` `Internal Server Error` (`http-http-proxy-unresolvable-host`). An authorizer function that raises is a `500` `AUTHORIZER_FAILURE` named `AuthorizerConfigurationException`, also with a null message, and an integration that times out a `504` `INTEGRATION_TIMEOUT` named `InternalServerErrorException` (`rest-*-authorizer-error`, `rest-*-timeout`); every 500-class response type is now recorded. HTTP APIs have fixed messages: an authorizer that raises answers `500` `Internal Server Error`, a timeout `503` `Service Unavailable` (`http-*-authorizer-error`, `http-*-timeout`) |
| CORS | Supported | Supported | REST CORS is a `MOCK` `OPTIONS` method and works as one. HTTP APIs send a preflight (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) that a route takes, through `ANY` or `OPTIONS`, to that route's integration after the route's own checks (so a preflight to a protected route is refused), and add `Access-Control-Allow-Origin`, `-Allow-Methods`, `-Allow-Headers`, and `-Max-Age` to the integration's answer only when both the origin and the requested method are allowed; a preflight no route takes is answered with `204` and the same headers. Other requests from an allowed origin get `Access-Control-Allow-Origin` and `-Expose-Headers`. Lists are joined with `,`, no `Vary` is sent, and CORS headers from the backend are dropped (`http-cors-*`). The gateway's own `204` answer, for a path with no route, follows the documentation; the reference API's `$default` route takes every path, so it is not recorded |
| Custom domains and API mappings | Partial | Partial | `--domain-name` serves every API mapped to a domain: API mappings with multi-level keys and routing rules (`routingMode`), the matched prefix stripped, reserved `/ping` and `/sping`, a certificate per domain by SNI. Unmapped requests answer `403 Forbidden`; the exact response API Gateway gives for each failure mode is not verified ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| Mutual TLS, `$context.identity.clientCert` | Partial | Partial | Custom domains with a truststore (read from S3) require a client certificate chained to it, unexpired, in the handshake; `clientCert` is available in access logs and Lambda events. A failed handshake closes the connection instead of answering 403; the chain length limit of four is not enforced; revocation is not checked, as on API Gateway ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| Client address | Supported | Supported | `--trusted-proxies`, PROXY protocol v2, and `X-Forwarded-Client-Cert` from trusted proxies; sent as `sourceIp` and `X-Forwarded-For` |

## Integrations

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| `HTTP_PROXY` | Supported | Supported | Forwards method, headers, body, and query string; path, query, and header mappings from method request parameters and literals; `timeoutInMillis`, bounded as API Gateway bounds it (50 ms minimum; REST has no 29 s cap, HTTP APIs cap at 30 s); streams the response; `tlsConfig` (`insecureSkipVerification` accepts any certificate, `serverNameToVerify` is the name verified and sent as SNI). Mappings from `method.request.*` (path, querystring, multivaluequerystring, header, multivalueheader, body, and JSON paths into the body), `context.*`, `stageVariables.*`, and literals work, including the `multivaluequerystring` and `multivalueheader` targets; other sources are ignored with a warning ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26)) |
| HTTP API parameter mapping (`overwrite:`, `append:`, `remove:`, response mapping) | n/a | Supported | `HTTP_PROXY` integrations: header, query string, and path mappings from `$request.*` (header, querystring, path, path parameters, simple JSON paths in the body), `$context.*`, `$stageVariables.*`, and static values, with `${...}` interpolation; response mappings by backend status code (headers and `overwrite:statuscode`) reading `$response.header.*` and `$response.body.*`. Reserved headers are refused as in API Gateway. Body paths support keys and array indexes only; API Gateway also refuses recursive descent and filters, and reads at most the first 100 KB of a body for a JSON path. Response mappings also apply to Lambda proxy and integration subtype responses. Request mappings also change a Lambda proxy event's headers and query string, as a deployed API does (`http-lambda-v2-request-mapping`); on subtypes `requestParameters` are the service parameters. `remove:` follows the documentation and is not recorded: an OpenAPI import, the way the reference stack is deployed, drops a `remove:` mapping with an empty value and drops the whole integration when the value is not empty |
| HTTP API request validation | n/a | Supported | HTTP APIs have no request validators; one named in a hand-written definition is ignored |
| `AWS_PROXY` Lambda, payload 1.0 and 2.0 | Supported | Supported | Events and responses follow the published formats: `requestContext` (`accountId` from the function ARN, `extendedRequestId`, `resourceId`, full `identity` nulls, `protocol`), `multiValueHeaders` merged with `headers`, cookies, base64 bodies, 2.0 response inference, and the client's header case for REST payload 1.0 (recovered from HTTP/1 request heads; HTTP/2 clients get lower case). Region from the function ARN, qualified ARNs and aliases, assumed integration roles, per-function endpoints (`--lambda-endpoint`), timeouts, and Lambda's 6 MB request/response limit (`502`). HTTP API `http.protocol` is the client's HTTP version, which API Gateway does not document but the deployed API reports (`http-lambda-v2-event`); `identity.clientCert` is reported for mutual TLS clients ([#40](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/40)) |
| `MOCK` | Supported | n/a | The request template is rendered as VTL, its `statusCode` selects the integration response by `selectionPattern`, and that response's parameters and template are applied ([#23](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/23), [#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27), [#28](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/28)). Output with no usable `statusCode` selects status 200 |
| `HTTP` (non-proxy) | Supported | n/a | Runs the template pipeline below against the backend; `timeoutInMillis`, `tlsConfig`, and `--vpc-link` apply as for `HTTP_PROXY`; the whole response is buffered (10 MB). Only mapped headers and mapped query parameters reach the backend, plus the headers API Gateway adds; the deployed API drops unmapped query parameters and unmapped headers the same way (`rest-http-nonproxy-template`, `rest-http-nonproxy-headers-*`). The request's `Content-Type` is passed on, and the backend is sent an `Accept` equal to it, else `application/json`, whatever `Accept` the client sent (`rest-http-nonproxy-headers-accept-*`) ([#28](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/28)) |
| `AWS` service integrations and non-proxy Lambda | Supported | n/a | SQS, SNS, DynamoDB, Step Functions, Kinesis, EventBridge, and S3 through `action/NAME` and `path/PATH` URIs (path placeholders filled from `integration.request.path.*`), and Lambda `.../functions/ARN/invocations` URIs, all through the request and response templates above. Requests are signed with SigV4 using the integration's `credentials` role (assumed through STS) or the gateway's credentials; `--aws-endpoint SERVICE=URL` points a service at an emulator. JSON-protocol services get their `X-Amz-Target` and content type from the service (`StartSyncExecution` goes to the `sync-states` endpoint); SQS and SNS `action/` URIs send `Action` in the query string. For Lambda, `selectionPattern` matches the function error's `errorMessage` (a successful invocation takes the default response) and `X-Amz-Invocation-Type: Event` answers `202`. Tested against local mocks that verify each signature, and compared live, the reference REST API against `apigw` on ECS calling the same resources, with `make parity-live`, for SQS `SendMessage`, DynamoDB `PutItem` and `GetItem` (a stored item and a missing one), Step Functions `StartSyncExecution`, EventBridge `PutEvents`, SNS `Publish`, Kinesis `PutRecord`, S3 `PutObject` and `GetObject` (and a missing object, mapped to `404` by `selectionPattern`), and non-proxy Lambda success and `selectionPattern` on a function error: status, content type, and body match apart from per-request values. Services are asked for JSON (`Accept: application/json`) unless the header is mapped, so SNS answers in JSON, not XML ([#29](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/29)) |
| HTTP API integration subtypes (SQS, EventBridge, Step Functions, Kinesis, AppConfig) | n/a | Supported | All ten subtypes: parameters from `requestParameters` (`$request.*`, `$context.*`, `$stageVariables.*`, static values, `${...}` interpolation) become the service request, a missing required parameter answers `500`, and the service's status, content type, and body are returned as they are. `Region` is the `Region` parameter, else the SQS queue URL's region, else the gateway's. An SQS queue URL contributes only its path, never its host. SQS answers in XML (`text/xml`) and Kinesis `Data` is Base64-encoded, as on a deployed API; Step Functions parameters become the camel-case members its API takes (`stateMachineArn`). `responseParameters` apply to the service's response by status code, as for `HTTP_PROXY`. All ten are compared live with `make parity-live`, including the service errors for an invalid SQS receipt handle and a missing Step Functions execution |
| VPC links and private integrations | Partial | Partial | `HTTP_PROXY` integrations with `--vpc-link CONNECTION_ID=URL` are served from that in-cluster URL (REST: the URI's host as the `Host` header; HTTP: the request path after the URL, with the stage prefix); a link with no mapping answers `501` with the reason on `/routes`. Load balancer and Cloud Map resolution is not attempted because those addresses are private to the VPC. No recorded fixture covers a VPC link yet |
| Response streaming (`responseTransferMode: STREAM`) | Supported | n/a | Lambda through `InvokeWithResponseStream` (`/response-streaming-invocations` URIs; metadata, 8 null bytes, payload) and `HTTP_PROXY`; 15 minute limit, 5 minute idle limit, `$context.integration.responseTransferMode` and `timeToAllHeaders`. Output that breaks the format answers `500`. Through `--lambda-endpoint` the emulator's HTTP body is streamed; function errors in HTTP trailers are not read |
| Integration credentials roles | Supported | Supported | Lambda routes assume the integration's `credentials` role, or use the gateway's own credentials with `--integration-credentials=gateway`; the role's trust policy must allow the gateway (see [deployment](deployment.md)) |
| Caller-credential passthrough (`arn:aws:iam::*:user/*`) | Not possible | Not possible | Needs IAM-authenticated callers; the route is not served (`501`) |
| AWS-generated backend client certificates | Out of scope | n/a | Supply your own certificate to the backend |
| Local integration overrides | Supported | Supported | `--integration-overrides` re-points routes; not an API Gateway feature |

## Mapping templates

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Velocity (VTL) engine: directives, Java value model, limits | Partial | n/a | The `apigw-vtl` crate parses and renders Velocity 1.7 templates (references, `#set`, `#if`, `#foreach` with the 1,000-iteration cap, `#break`, `#stop`, comments, whitespace gobbling, Java `toString` and arithmetic, `String`/`List`/`Map` methods) with output, step, and depth limits, checked against Apache Velocity 1.7, and renders every integration request and response template. `#macro`, `#parse`, `#include`, `#evaluate`, and `#define` are rejected; integers beyond 64 bits are an error where Java promotes to `BigInteger`; `Map` keys are strings ([#23](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/23)) |
| `$input`, `$util`, `$context`, `$stageVariables` | Partial | n/a | Implemented in `apigw-vtl`: `$input.body`, `json()`, `path()` (Jayway JsonPath 2.x: filters, slices, wildcards, deep scan, functions on definite and wildcard paths), `params()`, `$util` escaping, URL and Base64 helpers and `parseJson`, a caller-owned `$context` including `requestOverride` and `responseOverride`, and `$stageVariables`, all available to integration templates. JSON path functions after `..` are rejected ([#24](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/24)) |
| Java regular expressions (selection patterns, identity validation, `split`) | Partial | n/a | The `apigw-regex` crate translates `java.util.regex` to `fancy-regex` with Java's whole-string `matches`, ASCII classes, line terminators, replacement strings, and `split`, checked against real Java. Selection patterns, identity validation expressions, template `matches`/`replaceAll`/`replaceFirst`/`split`, and JSON path `=~` filters use it. `\G`, `\X`, `\b{g}`, `\p{javaXxx}`, Unicode blocks, case-insensitive back references, and `(?iu)` case comparison follow Java. Only `\N{name}` is refused at load time; case-insensitive back references on non-ASCII text, `\X` inside a look-behind, and characters newer than JDK 21's Unicode 15 can differ, as listed in [regex-engine.md](regex-engine.md). A pattern that exceeds the backtrack limit or cannot be translated fails the request (`500`) rather than counting as no match ([#22](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/22)) |
| Template output checked against a Velocity/Jayway oracle | Partial | n/a | `tools/vtl-oracle` renders about 9,500 templates with Apache Velocity 1.7 and Jayway JsonPath 2.9 in a pinned JDK image (operator matrix, whitespace matrix, random templates, JSON paths, hand-written gateway templates), and `apigw-vtl`'s `oracle` test compares output and `$context` for each; a weekly workflow re-renders the corpus, replays fresh random templates, and fuzzes. Four random cases still differ (Velocity's lexer state after a property reference and a directive). The oracle stubs AWS's `$input`/`$util`/`$context` wrappers, so those details await `TestInvokeMethod` against a deployed reference stack ([#25](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/25)) |
| Integration request: all `requestParameters` sources, templates by content type, `passthroughBehavior`, `contentHandling` | Supported | n/a | Sources `method.request.{path,querystring,multivaluequerystring,header,multivalueheader,body}`, body JSON paths, `context.*`, `stageVariables.*`, literals; targets path, querystring, multivaluequerystring, header, multivalueheader. The template for the request's `Content-Type` (whole value, then its media type; `application/json` when absent) is rendered; with none, `WHEN_NO_MATCH` passes the body through, `WHEN_NO_TEMPLATES` does so only when the integration has no templates, `NEVER` and the rest answer `415 Unsupported Media Type`. `$context.requestOverride.{path,querystring,header}` replace mapped values. `contentHandling` converts payloads between Base64 text and binary: a request is binary when its `Content-Type` matches the API's `binaryMediaTypes`, a response when the client's first `Accept` (else the backend's `Content-Type`) does; a payload that does not decode answers `500` ([#26](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/26)) |
| Integration response: `selectionPattern`, parameters, templates, method responses | Supported | n/a | Patterns are Java regular expressions matched against the whole backend status code; the first pattern in key order wins and `default` is used otherwise, and no match answers `500 Internal server error`. The response template is chosen by the first `Accept` media type that has one, else `application/json`, else the body passes through. `responseParameters` read `integration.response.{header,multivalueheader,body}`, body JSON paths, `context.*`, `stageVariables.*`, and literals; `$context.responseOverride.{status,header}` apply. A selected `statusCode` that the method does not declare answers `500` (skipped when the definition declares no method responses). Non-proxy responses carry only mapped headers and default to `Content-Type: application/json`. For non-proxy Lambda, patterns match the function error's `errorMessage` instead ([#27](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/27), [#29](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/29)) |

## Authorization and access control

Routes whose protection is not evaluated yet are refused, never served unprotected.

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Lambda authorizers (TOKEN, REQUEST) | Supported | Supported | REST `TOKEN` (with `identityValidationExpression`) and `REQUEST`; HTTP `REQUEST` with payload 1.0 and 2.0 and simple responses. Identity sources, result caching by identity sources and TTL (REST default 300 s, HTTP off), and the returned policy re-evaluated against each method ARN, cached or not. `401` for a missing identity source or a function that fails with `Unauthorized`, `403` for a denying policy, `500` for any other failure or an invalid response, and `10 s` timeout. `authorizerCredentials` roles are assumed. Differences: the method ARN's partition, region, and account come from the authorizer function's ARN; the validation expression runs through the Java regex translator, and an authorizer whose expression it cannot translate is refused with `401`; results are cached in the state backend (per replica in memory, or shared through `--valkey-url`), under a hash of the identity sources; `500` bodies use the default gateway response messages ([#31](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/31) REST, [#34](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/34) HTTP) |
| Cognito user pool authorizers | Supported | n/a | The token's signature is verified against the pool's published keys (fetched from `{issuer}/.well-known/jwks.json`, cached for 2 hours, refreshed when a token names an unknown key), `exp`/`nbf`/`iat` are checked, and the issuer must be one of the authorizer's pools. A route without scopes needs an ID token, a route with scopes an access token carrying one of them (`401` otherwise); an optional `identityValidationExpression` is matched against `aud`. Claims reach `$context.authorizer.claims` as strings (lists comma-joined, `exp` and `iat` as dates). The token may carry a `Bearer ` prefix ([#32](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/32)) |
| JWT authorizers (REST) | Supported | n/a | `type: jwt` with `jwtConfiguration.issuers` and `defaultAlgorithms`, the token read from the header the security scheme names (`in: header`), with or without a case-insensitive `Bearer ` prefix. The allowed algorithms among RS256/RS384/RS512/ES256/ES384/ES512 are accepted; HMAC and `none` never are. The issuer is matched exactly (trailing slash included) and its keys are found through OIDC discovery (`jwksUri` is ignored, as on import) and cached for up to an hour. `aud` (or `client_id` when there is no `aud`) must be one of that issuer's audiences, and `exp`/`nbf`/`iat` are checked with 60 seconds of skew: any of these failing is `401`. The issuer's `SINGLE_STRING` claim rules (required and/or one exact, case-sensitive expected value; an array never matches) and the method's scopes (one of them in `scope` or `scp`) answer `403` when they fail. Claims reach payload 1.0 events as `requestContext.authorizer.claims` with their JSON types, and mapping templates, parameter mappings, and access logs as JSON text with non-ASCII characters `\uXXXX`-escaped. A definition API Gateway would refuse (more than 10 issuers, 100 audiences, or 10 rules; a reserved or duplicate claim name; an unknown algorithm; a non-`https` issuer) answers `401` and is reported on `/routes` |
| JWT authorizers (HTTP) | n/a | Supported | RS256/RS384/RS512 tokens verified against the issuer's OIDC discovery document and key set (1.5 s timeout and 150 KB cap per fetch, keys cached 2 hours, at most one refresh per issuer every 30 s). `iss`, `aud` (or `client_id` when there is no `aud`), `exp`, `nbf`, and `iat` are checked; a route's scopes need one of them in `scope` or `scp` (`403` when missing, `401` for any other failure). Claims reach `$context.authorizer.claims` and `.scopes`, and `requestContext.authorizer.jwt` in payload 2.0 events. The token is what follows one exact `Bearer ` (or the whole value); `401` answers carry API Gateway's `WWW-Authenticate` header (see [Measured against deployed APIs](#measured-against-deployed-apis)). Differences: an authorizer with no audience or an `http` issuer is refused with `401`, and RSA-PSS is not accepted ([#33](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/33)) |
| API keys and usage plans (keys, quotas, plan throttles) | Supported | n/a | A method that requires a key admits an enabled key that belongs to a usage plan of the stage; otherwise `403 Forbidden` (`INVALID_API_KEY`). Key source `HEADER` (`x-api-key`) or `AUTHORIZER` (`usageIdentifierKey`). The plan's default and per-method throttles (most specific wins: `/path/METHOD`, then `*/*`, then the plan) answer `429 Too Many Requests` and its day, week, or month quota (UTC calendar periods, week from Monday) `429 Limit Exceeded` (`QUOTA_EXCEEDED`); a throttled request does not use up quota. Keys, plans, and associations are read live every `--usage-refresh-seconds` (60) with paced, paginated reads, and kept only as SHA-256 hashes; data older than an hour is not trusted. Differences: a key disabled in API Gateway keeps working until the next read; quota `offset` is not applied; with the in-memory state backend each replica counts its share of every limit, while `--valkey-url` counts exactly across replicas (if Valkey is unreachable, requests are admitted); a plan with a limit this gateway cannot read is dropped, so its keys are refused; HTTP APIs and `--openapi-file` sources cannot read keys, so key routes answer `403` ([#35](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/35)) |
| Request validators and models | Supported | n/a | Required query string and header parameters must be present and not blank (`400` `BAD_REQUEST_PARAMETERS`, message `Missing required request parameters: [a, b]`); bodies are validated against the model of the request's content type (else `$default`, else not validated) with JSON Schema draft 4, `$ref`s into `#/components/schemas/...` resolved against the API's models and nothing fetched from outside (`400` `BAD_REQUEST_BODY`, message `Invalid request body`). Parameters are checked before the body, both before throttling and the integration. Never skipped by `--insecure-skip-authorization`. See [Request validation](#request-validation) ([#36](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/36)) |
| Resource policies | Supported | n/a | Two-phase evaluation as in AWS's authorization-flow tables: an explicit `Deny` is checked before authentication; afterwards the policy is combined with a Lambda authorizer (an `Allow` from either suffices) or a Cognito user pool (both must allow), and alone when the route has no authorizer (an explicit `Allow` is required). Callers are anonymous (a `SigV4` signature cannot be verified), so only principals naming `*` apply. Conditions evaluated: `aws:SourceIp` (`IpAddress`/`NotIpAddress`, from the trusted client address), `aws:UserAgent`, `aws:Referer`, `aws:SecureTransport`, `aws:CurrentTime`/`aws:EpochTime`, with the string and date operators; any other condition, a qualifier, a policy variable, or a client address that could not be established counts as matching for a `Deny` and not matching for an `Allow`. `--insecure-skip-authorization` takes the authorizer to have allowed the caller but never skips the policy. A policy that cannot be read refuses every route with `403`. Denials answer `403` with AWS's message (`User: anonymous is not authorized to perform: execute-api:Invoke on resource: ... with an explicit deny in a resource-based policy` or `... because no resource-based policy allows the execute-api:Invoke action`), the account masked to its last four digits and taken from the ARNs in the policy ([#37](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/37)) |
| `AWS_IAM` authorization | Not possible | Not possible | A caller's SigV4 signature cannot be verified without their secret key. REST answers `403 Missing Authentication Token` and HTTP `403 Forbidden`, as API Gateway does for unsigned requests; `--insecure-skip-authorization` serves the route without a check |
| AWS WAF | Out of scope | n/a | Put a WAF or equivalent in front of the gateway |

## Throttling, caching, and releases

| Feature | REST | HTTP | Behavior today / issue |
|---|---|---|---|
| Stage, method, and route throttling (`429`) | Supported | Supported | Token buckets per method (REST `methodSettings`, `*/*` default) and per route (HTTP route settings, default route settings); `429` through the `THROTTLED` gateway response (REST) or `{"message":"Too Many Requests"}` (HTTP). Usage-plan throttles apply per API key (see [API keys and usage plans](#authorization-and-access-control)). Buckets are per replica unless `--valkey-url` shares them (see below). The account-level quota (10,000 requests per second per Region across every API in the account) is an AWS service quota, not part of the API, and is not applied |
| Shared limiter state across replicas | Supported | Supported | With `--valkey-url`, throttle buckets, usage-plan quotas, the Lambda authorizer cache, and the response cache live in Valkey, so every replica counts against the same limits and `--replicas` no longer divides them. Each call has a 500 ms timeout; when Valkey is unreachable a throttle or quota check admits the request and a cache lookup is a miss. Without it state is in memory per replica: `--replicas N` divides throttle rates and bursts by `N`, so the API-wide rate is approximately the configured one (a replica's bucket holds at least one token, so with more replicas than burst tokens the API-wide burst is larger) |
| Response caching | Partial | n/a | Method caching with TTL, cache key parameters, the 1 MB entry cap, and `Cache-Control: max-age=0` handling per `requireAuthorizationForCacheControl` and the unauthorized strategy, in the state backend: per replica in memory, or shared between replicas through `--valkey-url`, where entries are stored unencrypted whatever `cacheDataEncrypted` says ([#110](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/110)). Differences: only 2xx responses are cached; a client is never authorized to invalidate, so authorization-required methods treat every `max-age=0` as unauthorized; cache encryption and cluster size do not apply; the exact `403` body for `FAIL_WITH_403` is the `ACCESS_DENIED` default ([#38](https://github.com/smoketurner/amazon-apigateway-self-hosted/issues/38)) |
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

## Fidelity limits of the export

- REST control-plane reads (`GetResources`, `GetAuthorizers`, ...) return the draft, not the
  deployment. Only `GetExport` for a stage and HTTP `ExportApi` with a stage name reflect what
  is deployed, so the export is the structural source and usage plans, API keys, and domain
  mappings are read live.
- A canary deployment cannot be exported. The canary release is built from the stage's export
  unless `--canary-export-stage` supplies a stage that holds the canary deployment.
- Control-plane calls share a 10 requests per second per-account limit, so refreshes are
  conditional and jittered.

## Measured against deployed APIs

The reference stack ([terraform/README.md](../terraform/README.md)) deploys real REST and HTTP
APIs, and the fixtures under `parity/` are recordings of what they answer. The behavior below is
not in API Gateway's documentation, or differs from it; `apigw` follows what the deployed APIs
do.

**Gateway responses (REST)**

- `$context.error.messageString` starts with a space for failures of a request that has started
  executing (`{"message": "Internal server error"}`, and the same for `BAD_REQUEST_BODY`,
  `BAD_REQUEST_PARAMETERS`, `UNSUPPORTED_MEDIA_TYPE`, `INTEGRATION_FAILURE`, `INTEGRATION_TIMEOUT`,
  `API_CONFIGURATION_ERROR`), in customized templates too. Failures that turn a request away
  earlier have none (`{"message":"Forbidden"}`).
- An uncustomized `ACCESS_DENIED` uses the key `Message`, not `message`.
- The `413` is the plain text `HTTP content length exceeded 10485760 bytes.` with
  `content-type: text; charset=utf-8` and no `x-amzn-errortype`.
- `x-amzn-errortype` is `TooManyRequestsException` for `THROTTLED` and `BadRequestException` for
  `UNSUPPORTED_MEDIA_TYPE`.

**Paths**

- REST: slashes after the last segment and extra slashes before the first do not take part in
  routing (`/pets/` and `//pets` are `/pets`); a doubled slash between segments does. Path
  parameters are never percent-decoded, in Lambda events, `$input.params()`, and integration URLs.
  A `%` that does not start an escape, in the path or query string, answers `400` with no body.
- HTTP: the path is percent-decoded and runs of slashes are collapsed before routing, and
  `rawPath`, `$context.path`, and path parameters use that form. A trailing slash is part of the
  path (`/pets/` is not `/pets`). A greedy parameter under a prefix may be empty (`/files/`).

**Query strings to HTTP backends (REST)** are written again rather than forwarded: a space becomes
`+`, the characters RFC 3986 allows in a query stay bare, and the rest are escaped. API Gateway
also leaves `'` bare; `apigw` sends `%27`.

**Lambda events**

- Every event carries `X-Forwarded-For`, `X-Forwarded-Port`, `X-Forwarded-Proto`, and
  `X-Amzn-Trace-Id` (`Root=...`, or `Self=...;` before what the client sent), whatever the client
  sent under those names.
- Header names: REST payload 1.0 keeps the client's spelling except `Host`, `User-Agent`, and
  `Authorization`; HTTP API payload 1.0 does the same and also spells `Cookie` and
  `Content-Length` itself and lower-cases `accept`; payload 2.0 is lower case.
- REST events leave out `Content-Length`; HTTP API events always carry it, `0` for no body.
- No event carries a hop-by-hop header the client sent (`Connection`, `Keep-Alive`, `TE`,
  `Upgrade`, `Proxy-Connection`).
- A repeated request header is its last value in payload 1.0 `headers` and every value in
  `multiValueHeaders`, REST and HTTP alike, except that an HTTP API's payload 1.0 joins repeated
  `Cookie` headers into one `a=1; b=2` value. Payload 2.0 joins repeats with commas. A REST
  `method.request.header.*` mapping takes the last value (`*-repeated-*` cases).
- REST `requestContext` has no `authorizer` key when no authorizer ran, carries
  `authorizer.integrationLatency` when a Lambda authorizer did, and names the `deploymentId` and,
  when the gateway may call `GetResources`, the `resourceId`.
- HTTP API payload 1.0 has `version: "1.0"`, the route key as `resourceId`, `identity.cognitoAmr`,
  and a `path` that is the path as sent, stage and escapes included.

**Response headers (REST)**

- Every response carries `x-amz-apigw-id`, not only the ones API Gateway generates.
- A response from any integration but `MOCK` carries `X-Amzn-Trace-Id`; an `HTTP_PROXY` backend's
  own value passes through.
- An `HTTP_PROXY` backend's `x-amzn-RequestId` becomes `x-amzn-Remapped-x-amzn-RequestId`, and its
  `Content-Length` is repeated as `x-amzn-Remapped-Content-Length`. Neither is in the documented
  header table.

**Other**

- A Lambda proxy response's `statusCode` must be 100 through 599. Anything else, like a function
  error, is a `502` whose `x-amzn-errortype` is `InternalServerErrorException`.
  `$context.error.responseType` tells the two apart: a function error is an `INTEGRATION_FAILURE`,
  a response nothing can be made from is only a `DEFAULT_5XX`.
- A request no route claims that has an `Authorization` header is read as a failed attempt at
  Signature Version 4: `403` `IncompleteSignatureException`, with a message naming what the header
  lacks and its SHA-256 digest. Signature parameters in the query string are read the same way. A
  complete signature is judged by its date next (`Date must be in ISO-8601 'basic format'`,
  `Signature expired`, `Signature not yet current`) and then by its credentials.
- A response to `HEAD` from an integration repeats its length as `x-amzn-Remapped-Content-Length`.
- An `HTTP_PROXY` backend receives the client's own `x-amzn-apigateway-api-id` when it sent one.
- In a request template a body of `null` reads as `{}`; nulls inside a body are kept.
- A header value that is not ASCII reaches an HTTP backend byte for byte, also through a
  parameter mapping. In a REST Lambda event it is not decoded: each byte above 127 appears as the
  character U+FF00 plus the byte.
- `X-HTTP-Method-Override` is consumed: neither a Lambda event nor an HTTP backend sees it.
- `TRACE` never reaches a REST API. The endpoint answers `405` with a small HTML page and, like the
  `400` for a malformed escape, no `x-amzn-RequestId` or `x-amz-apigw-id`.
- An `HTTP_PROXY` backend receives the client's `Via` (the documented header table says it is
  dropped) and `Content-Length: 0` for a body-less request of any method but `GET` and `HEAD`.

- A response API Gateway generates for a `HEAD` request has `content-length: 0`.
- AWS service integrations receive the request's `X-Amzn-Trace-Id`, which Step Functions reports
  back as `traceHeader`.

**HTTP APIs**

- A Lambda function gets the body as text only when the request's `Content-Type` is one API
  Gateway takes for text: `text/` followed by letters, digits, `+`, and `-`; `application/json`,
  `xml`, `javascript`, `x-javascript`, `ecmascript`, `x-ecmascript`, `graphql`, or `x-yaml`; or
  `application/` followed by letters, digits, and `-` and then `+json` or `+xml`. At most one
  parameter may follow, and a `charset` must be `utf-8` or `us-ascii`. Every other type, and a
  body with no type, is base64-encoded: `application/x-www-form-urlencoded`,
  `application/vnd.api+json`, and `application/yaml` among them. Text that is not UTF-8 is not
  encoded either; the bytes that do not decode become U+FFFD.
- A JWT authorizer's `401` says why in `WWW-Authenticate`: `Bearer` when the request has no
  token, otherwise `Bearer scope="<the route's scopes>" error="invalid_token"
  error_description="..."`, the description in the words of the Go libraries API Gateway reads
  tokens with (`token contains an invalid number of segments`, `illegal base64 data at input
  byte 1`, `signing method HS256 is invalid`, `no "kid" provided in the JWT`, `crypto/rsa:
  verification error`, and so on). `apigw` gives the same description for all 53 refused
  tokens sent to both. It gives none where it cannot know API Gateway's words: JSON that goes
  wrong inside an object, array, string, or number, a wrong issuer, an
  issuer whose keys cannot be fetched, and `nbf` or `iat` in the future. `the token has expired`
  and `the token does not have a valid audience` come from AWS's documentation, not from a
  measurement: no signed token was available to send.
- A token is found by taking one `Bearer ` off the identity source's value, spelled exactly so:
  `bearer <token>` is refused.
- With one issuer, the token is verified with that issuer's keys whatever its `iss` says, and
  the issuer is compared afterwards.
- A function error or a malformed proxy response answers `500`
  `{"message":"Internal Server Error"}`; an HTTP backend that cannot be reached answers `502`
  `{"message":"Internal server error"}`.
- `TRACE` and a path with a malformed percent-escape get the load balancer's HTML `405` and
  `400` pages, as on a REST API. An odd query string or repeated slashes are passed on as sent.
- The stage root with a trailing slash (`/ref/`) reaches the API's root.
- Payload 1.0 events have no `deploymentId` and spell `Content-Type` so.
- `GET /mapped/a%20b?q=x%20y`, a route whose parameter mapping copies a query value holding a
  space, answers an HTML `502` on API Gateway. `apigw` serves the request.

**Request templates** read the body leniently: an empty body is `{}`, what follows the first JSON
value is ignored, and a body that is not JSON is a string. A body that opens an object, array, or
string and does not hold one answers `400` `{"message": "Could not process payload"}`.

Known differences that remain:

- A request whose backend URL would have a `.` or `..` path segment (written plainly or as
  `%2e`) is refused with `400` `{"message":"Bad Request"}` and never reaches the backend. API
  Gateway sends such segments as they are; `apigw` does not, so that a client cannot reach a
  backend path outside the one the route names.
- API Gateway answers `403` to a request whose `Host` is not the API's. `apigw` does the same
  for hosts outside `--allowed-host`, but serves any host when the flag is not given: it has no
  name of its own to compare with.
- A complete signature whose date is current is always an `UnrecognizedClientException`: a
  gateway outside AWS cannot look the credentials up.

- Response header names are lower case. API Gateway writes them in mixed case over HTTP/1.1
  (`Content-Type`, `x-amzn-RequestId`); over HTTP/2 both are lower case.

- `X-Forwarded-For` holds the address `apigw` established for the client. API Gateway appends
  that address to whatever the client sent; `apigw` only keeps a client's value from a trusted
  proxy ([deployment.md](deployment.md#client-ip)). The same holds for the `for=` list in an
  HTTP API's `Forwarded` header, which also lacks API Gateway's `by=<egress address>`.
- `X-Forwarded-Port` is the port in the `Host` header, `443` when it names none. API Gateway
  always says `443`.

## Request validation

Differences from API Gateway's validators:

`$context.error.validationErrorString` reads as API Gateway's does. API Gateway validates with the
Java `json-schema-validator` library, and this gateway follows that library's evaluation: the same
message texts (for example `[object has missing required properties (["name"])]`), a member or
element looked into only while nothing has failed yet, one message for a failed
`allOf`/`anyOf`/`oneOf`/`not`, a `format attribute "..." not supported` warning beside the errors,
the distinct messages in the order of a Java `HashSet`, numbers printed as Java prints them, and the
text escaped like a Java string literal when a template renders it. A body that is not JSON, or is
empty, reports `[Unknown error parsing request body]`; bytes that are not UTF-8 are read as U+FFFD
and only the first JSON value of a body counts. `crates/apigw/tests/fixtures/rest-validation-errors.jsonl`
holds 109 request bodies with the reference REST API's answers, all reproduced; keywords the
reference model does not use (`enum`, `maximum`, `multipleOf`, `maxLength`, `pattern`, the array
and property count keywords, `uniqueItems`, `dependencies`, `allOf`/`anyOf`/`oneOf`/`not`) follow the
library's source and message catalog and are not measured.

Differences from API Gateway's validators:

- An integer outside the 64-bit range is read as a floating-point number, so it fails
  `type: integer` and prints with an exponent; `-0` is likewise read as `-0.0`. A number too large
  for a double (`1E400`) is an unreadable body here and a `500` at API Gateway.
- An `integer` schema without a `format` is taken to have API Gateway's `int32`, which its
  validator reports as not supported whenever such a value is checked in a failing request. The
  export does not say whether a model was written that way or imported from OpenAPI.
- A report longer than 1 MiB is cut off. The default `BAD_REQUEST_BODY` response does not include
  the report.
- `pattern` expressions are ECMAScript regular expressions translated to Rust's syntax, and a
  `format` is not enforced.
- An empty body, malformed JSON, and a body that is not valid JSON are all `Invalid request body`
  when a model applies to the request's content type; a request without `Content-Type` is treated as
  `application/json`.
- A `$ref` that is not a model of the API (a missing model, or an external URL or file) makes the
  route answer `501` instead of being fetched; `/routes` gives the reason.
- Parameters are matched by name as declared: header names ignore case, query names do not. Path
  parameters are always present on a matched route, and a cookie parameter is not checked.
