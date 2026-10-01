# Architecture

One crate, `crates/apigw`, building one binary.

| Module | Responsibility |
|---|---|
| `config` | clap CLI/env configuration |
| `source` | Downloads the OpenAPI export and stage variables (`GetExport`/`GetStage` for REST, `ExportApi`/`GetStage` for HTTP APIs) or reads a file; reads/writes the last-known-good cache |
| `spec` | Parses the export's `paths` and `x-amazon-apigateway-integration` objects into `Route`s, applying stage variables and integration overrides |
| `router` | Builds an axum `Router` from the routes; the dispatcher that swaps routers live; admin routes |
| `gateway` | Per-request execution: authorization gate, body buffering, API Gateway-shaped errors |
| `proxy` | `HTTP_PROXY` forwarding |
| `lambda` | `AWS_PROXY` event construction (payload 1.0 and 2.0) and response mapping |
| `listener` | TLS accept loop, PROXY protocol v2, certificate reload |
| `identity` | Client address and forwarded client certificate, from the peer and trusted proxies' headers |
| `app` | Startup, refresh loop, shutdown |

## Loading and refreshing

```text
Fetcher::fetch ─► Snapshot { kind, api_id, stage, stage_variables, openapi }
                    │  (written to --config-cache)
                    ▼
ApiDefinition::from_openapi(openapi, kind, stage vars + local overrides, integration overrides)
                    ▼
router::build ─► Loaded { router, summary } ─► watch::Sender<Arc<Loaded>>
```

The refresh loop rebuilds only when the snapshot or the override file changed. A build
failure keeps the current `Loaded` in place.

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
