# CI/CD

- **`.github/workflows/ci.yml`** — `fmt`, `clippy` (`--locked -D warnings`), `test`
  (`cargo test --locked`, Linux + macOS), and `license-check`
  (`cargo-deny check`, which also enforces the OpenSSL/`ring` bans). Toolchain from
  `rust-toolchain.toml`; actions SHA-pinned; `permissions: {}` top-level with per-job
  `contents: read`.
- **`parity-replay` job** — builds `apigw` and `apigw-parity` and runs
  `apigw-parity replay`: it serves the recorded exports with `apigw` and diffs its answers
  against `parity/fixtures/`. Needs no AWS access. See [parity/README.md](../parity/README.md).
- **`.github/workflows/parity.yml`** — nightly (and manual): assumes the GitHub OIDC role from
  `terraform/environments/dev`, downloads the reference APIs' exports, runs `apigw-parity record`,
  and opens or updates a `parity-drift` issue when API Gateway no longer matches the committed
  fixtures. Drift never fails the run. It only works once the reference stack is deployed and
  the repository variables and secrets in [terraform/README.md](../terraform/README.md) are
  set; until `PARITY_AWS_ROLE_ARN` is set the job is skipped. The role it assumes can only
  read the reference APIs' stages and exports (`apigateway:GET`).
- **`.github/workflows/secure_workflows.yml`** — fails CI if any third-party action is not
  pinned to a full commit SHA.
- **`.github/dependabot.yml`** — `cargo`, `github-actions`, and `docker`, weekly, grouped,
  7-day cooldown.

Not yet wired up: building and publishing the container image, and scanning it. When adding
them, keep `--locked` on every cargo invocation, `persist-credentials: false` on checkout,
and pin each action to a SHA (`gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`).
