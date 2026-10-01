# CI/CD

- **`.github/workflows/ci.yml`** — `fmt`, `clippy` (`--locked -D warnings`), `test`
  (`cargo test --locked`, Linux + macOS), and `license-check`
  (`cargo-deny check`, which also enforces the OpenSSL/`ring` bans). Toolchain from
  `rust-toolchain.toml`; actions SHA-pinned; `permissions: {}` top-level with per-job
  `contents: read`.
- **`.github/workflows/secure_workflows.yml`** — fails CI if any third-party action is not
  pinned to a full commit SHA.
- **`.github/dependabot.yml`** — `cargo`, `github-actions`, and `docker`, weekly, grouped,
  7-day cooldown.

Not yet wired up: building and publishing the container image, and scanning it. When adding
them, keep `--locked` on every cargo invocation, `persist-credentials: false` on checkout,
and pin each action to a SHA (`gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`).
