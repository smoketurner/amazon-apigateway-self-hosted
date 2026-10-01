# Architecture

One crate, `crates/apigw`, building one binary.

| Module | Responsibility |
|---|---|
| `config` | clap CLI/env configuration |
| `source` | Checks the stage with `GetStage` and downloads the export (`GetExport` for REST, `ExportApi` for HTTP APIs) only when the deployment changed, or reads a file; reads/writes the last-known-good cache |
| `model` | `ApiModel`: everything imported from the export and `GetStage` (operations, integrations, protections, authorizers, validators, models, gateway responses, API and stage settings), whether or not it is enforced yet; integration overrides apply here |
| `integration`, `route` | Compile each model operation into a runtime `Route` with an executable `Integration`, substituting stage variables |
| `router` | Builds an axum `Router` from the routes; the dispatcher that swaps routers live; admin routes |
| `gateway` | Per-request execution: authorization gate, body buffering, API Gateway-shaped errors |
| `proxy` | `HTTP_PROXY` forwarding |
| `lambda` | `AWS_PROXY` event construction (payload 1.0 and 2.0) and response mapping |
| `listener` | TLS accept loop and certificate reload |
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
accept → TCP_NODELAY → connection cap → spawn → TLS handshake (5 s)
  → hyper-util auto HTTP/1 + HTTP/2 (10 s header read, idle limit, h2 keep-alive)
```

The task is spawned before any per-connection I/O, so a slow handshake never blocks
`accept`. On shutdown the listener stops accepting and gives open connections 30 s to finish.
