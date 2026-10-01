# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

It also drives the `rust-agents` Claude Code plugin (conventions live in `.claude/rules/`).

## What this is

`apigw`: a self-hosted Amazon API Gateway. A single Rust binary (`crates/apigw`, plus pure library crates)
that downloads an existing REST or HTTP API's OpenAPI export from API Gateway, builds an
axum router from it, serves it over TLS, and swaps the router live as the API changes. It
runs as a container on Kubernetes (often behind Istio) on non-AWS clouds or on-prem.

- Edition 2024, resolver 3, toolchain pinned in `rust-toolchain.toml`
- **aws-lc-rs** is the only crypto/TLS provider (never OpenSSL or `ring`)
- axum + hyper (driven directly by `listener.rs`), reqwest for `HTTP_PROXY`, AWS SDK for
  API Gateway exports and Lambda

## Repository layout

```
Cargo.toml            # virtual workspace: pinned deps + strict lints + profiles
crates/apigw/src/     # the binary — module map in docs/architecture.md
crates/apigw-regex/   # java.util.regex translator (library, pure)
tools/                # Docker-run Java oracles that generate test fixtures
docs/                 # architecture, deployment (k8s/Istio), crypto, CI
Dockerfile            # static musl build → distroless
.claude/rules/        # review gates, branching, commits, continuous improvement
```

## Conventions

- **Lints are strict and inherited** (`[lints] workspace = true`): panics, indexing, lossy
  casts, and unchecked arithmetic are denied; clippy `pedantic` is on. In tests, opt out
  narrowly with `#[expect(clippy::unwrap_used, reason = "...")]`.
- **Dependencies are pinned** `=x.y.z` with `default-features = false` in
  `[workspace.dependencies]`; look up the current version when adding one.
- The `apigw` binary crate keeps items `pub(crate)`; library crates (`apigw-regex`) expose a
  documented `pub` API.
- Own-crate items are imported with `use`, not written as deep `crate::` paths
  (`clippy::absolute_paths`); a new workspace dependency also goes in `.clippy.toml`'s
  `absolute-paths-allowed-crates`.
- **Errors:** `thiserror` for module error types, `anyhow` in `app.rs`/`main.rs`.
- **Logging:** `tracing`, never `println!`. **Time:** `jiff`. **Request IDs:** UUID v7.
- **Commits:** Conventional Commits (`.claude/rules/commits-and-issues.md`). Never push to
  `main` — branch and PR.

## Project rules

Read **`.claude/rules/code-standards.md`** before implementing or reviewing — it holds the
gateway invariants the compiler can't catch (mandatory TLS, panic-free route building,
fail-closed authorization, API Gateway fidelity). `.claude/rules/development-discipline.md`
covers how work is carried out.

## Common commands

```bash
make lint      # cargo clippy --workspace --all-targets --all-features -- -D warnings
make test      # cargo test --workspace --all-features
make deny      # cargo deny check
make image     # docker build -t apigw:local .
cargo test -p apigw <test_name>
```
