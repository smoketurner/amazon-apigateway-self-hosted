# Architecture

`crates/apigw` builds the binary. `crates/apigw-regex` is a pure library with no I/O: it translates
Java regex syntax to `fancy-regex` and provides Java's matching, replacement, and split semantics
(see its crate docs for the known differences from Java).

| Module | Responsibility |
|---|---|
| `config` | clap CLI/env configuration |
| `source` | Checks the stage with `GetStage` and downloads the export (`GetExport` for REST, `ExportApi` for HTTP APIs) only when the deployment changed, or reads a file; reads/writes the last-known-good cache |
| `model` | `ApiModel`: everything imported from the export and `GetStage` (operations, integrations, protections, authorizers, validators, models, gateway responses, API and stage settings), whether or not it is enforced yet; integration overrides apply here |
| `integration`, `route` | Compile each model operation into a runtime `Route` with an executable `Integration`, substituting stage variables |
| `router` | Builds an axum `Router` from the routes; the dispatcher that swaps routers live; admin routes |
| `client_cert` | The client certificate as API Gateway reports it (`clientCertPem`, `subjectDN`, `issuerDN`, `serialNumber`, `validity`) |
| `domain` | Custom domains: API mappings, routing rules, mutual TLS truststores, and the supervisor that loads and refreshes one API per mapped stage |
| `observability` | Access logs, per-minute EMF metrics, and execution logs: `StageObserver` records each request of a loaded stage; `Observability` owns the bounded per-destination queues and workers |
| `pipeline` | Per-request execution in API Gateway's stage order (`Pipeline`), and `RequestContext`, the single owner of `$context` variables |
| `gateway` | What every route of an API shares (`ApiContext`), enforcement of unevaluated protections, and API Gateway-shaped errors (`GatewayError`) |
| `gateway_response` | Every error the gateway answers with (`Failure`), rendered through the API's customized REST gateway responses (status, `gatewayresponse.header.*`, `$context` templates, `DEFAULT_4XX`/`DEFAULT_5XX` fallback) or HTTP APIs' fixed messages |
| `authz` | Compiles the API's authorizers (`Authorizers`, per route `RouteAuthorizer`) and evaluates them before the integration: Lambda authorizers with identity sources, a bounded TTL cache, and IAM policy evaluation (`PolicyDocument`, `MethodArn`, wildcard `Glob`); token authorizers (`authz::jwt`): Cognito and HTTP API JWT verification against an issuer's cached public keys (`KeyStore`); resource policies (`authz::resource_policy`, `authz::condition`): the two-phase evaluation and the outcome tables as `Verdict::combine`, with `aws:SourceIp` from `identity`; `Denial` maps each refusal to its gateway response |
| `state`, `throttle` | `StateBackend` (token buckets, period quota counters, TTL cache; in-memory today, shaped for a shared Valkey backend) and the stage throttle settings that become one bucket per route |
| `digest` | SHA-256 digests, so credentials never appear in cache keys |
| `cors`, `http_routes`, `mapping` | HTTP API CORS (preflight answers and response headers), route selection by path and method together for HTTP APIs, and `requestParameters`/`responseParameters` mapping for `HTTP_PROXY` |
| `vpc_link` | `--vpc-link` mappings from a VPC link connection ID to an in-cluster base URL, used when compiling `HTTP_PROXY` integrations |
| `aws` | `AwsClients`: per-region Lambda clients, assumed integration-role credentials, Lambda endpoint overrides, trace header propagation |
| `proxy` | `HTTP_PROXY` forwarding |
| `lambda`, `lambda_response` | `AWS_PROXY` event construction (payload 1.0 and 2.0), invocation (buffered `Invoke` or streamed `InvokeWithResponseStream`), and response mapping |
| `header_case` | Recovers the client's HTTP/1 header name spelling (hyper keeps it private) by watching request heads on the connection |
| `listener` | TLS accept loop, PROXY protocol v2, certificate reload |
| `identity` | Client address and forwarded client certificate, from the peer and trusted proxies' headers |
| `app` | Startup, refresh loop, shutdown |

## Loading and refreshing

```text
Fetcher::fetch(current stamp) ─► Unchanged | Snapshot { kind, api_id, stage, stamp, stage_settings, openapi }
                    │  (written to --config-cache; the raw export is cached, so importer fixes apply to it)
                    ▼
ApiModel::import(openapi, kind, stage settings + local variable overrides, integration overrides)
                    ▼
router::build ─► Route::compile per operation ─► Loaded { router, summary } ─► watch::Sender<Arc<Loaded>>
```

Each refresh calls `GetStage` and re-exports only when the deployment ID or last-updated time
changed, because control-plane calls share a 10 req/s per-account limit. Failures back off
exponentially (up to 15 minutes, with jitter). The loop rebuilds only when the snapshot or the
override file changed; a build failure keeps the current `Loaded` in place and is logged once.

Anything imported but not enforced yet is listed as a `Feature` on `/routes`, per API and per
route, so the gap to API Gateway is visible and each change that closes one removes it.

## Routing

API Gateway paths map to axum paths: `{name}` stays, `{name+}` becomes `{*name}`. Routes are
grouped by path, and each path gets a single `any(...)` handler that selects the integration
by method (exact method, then `ANY`, then the HTTP API `$default` route), because axum
panics on overlapping method routes and API Gateway allows `ANY` next to explicit methods.

axum also panics on conflicting paths. Each path is first inserted into a `matchit` router of
the same version axum uses; a path that conflicts is skipped and reported on `/routes`
instead of aborting the process. axum's 0.7-syntax checks are disabled because API Gateway
paths may contain segments beginning with `:` or `*`. A property test feeds arbitrary paths
through `router::build` to keep it panic-free.

The dispatcher reads the current `Loaded` once per request and calls its router, so a swap
never affects a request already in progress.

## Accept loop

`listener::serve` drives hyper directly instead of `axum::serve`, which installs no timer and
so leaves hyper's header-read timeout disabled:

```text
accept → TCP_NODELAY → connection cap → spawn → PROXY header (5 s, when enabled)
  → TLS handshake (5 s) → hyper-util auto HTTP/1 + HTTP/2 (10 s header read, idle limit, h2 keep-alive)
```

The task is spawned before any per-connection I/O, so a slow handshake never blocks
`accept`. On shutdown the listener stops accepting and gives open connections 30 s to finish.

For every request the listener calls `TrustedProxies::identify` with the connection's peer,
which attaches a `ClientIdentity` to the request's extensions and rewrites `X-Forwarded-For`
and `X-Forwarded-Client-Cert` to match. `gateway::handle` reads the source IP from it, and
integrations only ever see the rewritten headers.

## Parity harness

`crates/apigw-parity` is a dev tool, not part of the gateway. `replay` starts the `apigw`
binary with `--openapi-file` pointing at a recorded export, `--base-path /<stage>`, the
recorded stage variables, and an `--integration-overrides` file that moves every integration
built from the `echo_host` stage variable to an in-process echo server over plain HTTP. Every
Lambda function the export invokes gets a `--lambda-endpoint` pointing at the same server, which
speaks Lambda's Invoke protocol. It then sends the case requests over TLS and diffs the responses
against fixtures recorded from real API Gateway. Everything it needs from `apigw` is public: the
flags above and the admin `/healthz` endpoint. See [parity/README.md](../parity/README.md).
