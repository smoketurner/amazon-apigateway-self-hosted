# Code Standards — review gates

Invariants the compiler does **not** catch. Read before implementing or reviewing a change.

> The `rust-agents` plugin does **not** auto-load this file. Its agents read
> `commits-and-issues.md`, `branching.md`, and `continuous-improvement.md`, each of which
> points here, and the main session reaches it through `CLAUDE.md`. Keep those pointers.

## TLS & crypto → [docs/crypto.md](../../docs/crypto.md)

- [ ] **Every listener terminates TLS.** No plaintext listener, no `--no-tls` flag, no
      80→443 redirect.
- [ ] **aws-lc-rs is the only crypto provider.** No `openssl`, `native-tls`, or `ring`
      features; AWS SDK crates use `default-https-client`, never `rustls`/`legacy-https-client`.
- [ ] The default provider is installed once at the top of `main`.
- [ ] After touching TLS deps: `cargo tree -i ring` and `cargo tree -i openssl-sys` match
      nothing; `cargo deny check` passes.

## Never crash on API definitions → [docs/architecture.md](../../docs/architecture.md)

- [ ] Nothing derived from an API Gateway export, override file, or cache may reach a
      panicking API. axum's `Router::route`/`nest` panic on invalid or conflicting paths:
      every path goes through `axum_path` and the `matchit` pre-check, and routers keep
      `without_v07_checks()`. The release profile uses `panic = "abort"`.
- [ ] A definition that fails to build is rejected as a whole; the current routes keep
      serving.
- [ ] `build_never_panics` (proptest) stays green; extend it when route building changes.

## Fail closed

- [ ] Routes with an authorizer, IAM auth, or API key requirement answer `401` unless
      `--insecure-skip-authorization` is set. New integration types must not bypass the gate
      in `gateway::handle`.
- [ ] Integrations that can't be served faithfully (VTL mapping templates, VPC links) answer
      `501` and are reported on `/routes`, never approximated silently.

## API Gateway fidelity

- [ ] Error bodies match API Gateway (`{"message": ...}`, REST `403 Missing Authentication
      Token` vs HTTP `404 Not Found`, `502`/`504` for integration failures).
- [ ] Lambda events follow the published payload format 1.0/2.0 shapes; responses follow
      API Gateway's parsing rules.
- [ ] Proxies never forward hop-by-hop headers and never follow redirects.

## Workspace hygiene

- [ ] `[lints] workspace = true`; dependencies pinned `=x.y.z`, `default-features = false`,
      added to `[workspace.dependencies]` (current version looked up). No comments in
      `Cargo.toml` files.
- [ ] Panics opt out narrowly in tests only (`#[expect(..., reason = "...")]`).
- [ ] Own-crate items are imported with `use`, never spelled as `crate::a::b::C` in code
      (`clippy::absolute_paths`). A new dependency in `[workspace.dependencies]` is also added
      to `absolute-paths-allowed-crates` in `.clippy.toml`.
- [ ] IDs use `Uuid::now_v7()` (uuid's `v4` feature stays disabled, so v4 cannot be
      called) and time uses `jiff` (`clippy::disallowed_methods` bans `SystemTime::now`).
- [ ] `thiserror` for module errors, `anyhow` at the binary edge; `tracing`, never `println!`.

## Before opening a PR

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo deny check
```
