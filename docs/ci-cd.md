# CI/CD

- **`.github/workflows/ci.yml`** — `fmt`, `clippy` (`--locked -D warnings`), `test`
  (`cargo test --locked`, Linux + macOS), and `license-check`
  (`cargo-deny check`, which also enforces the OpenSSL/`ring` bans). Toolchain from
  `rust-toolchain.toml`; actions locked (see below); `permissions: {}` top-level with per-job
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
- **`.github/workflows/actions.lock`** — the workflow lockfile. Workflows reference actions by
  `vX.Y.Z` tag and the lockfile records the commit SHA each tag resolves to. It is generated;
  after adding or changing a `uses:` line, run `gh actions-lock`
  (`gh extension install github/gh-actions-lock`) and commit the result.
- **`.github/workflows/verify-lockfile.yml`** — runs `gh actions-lock --verify`, which fails when
  the lockfile is out of sync with the workflows or a locked pin no longer verifies upstream.
- **`.github/dependabot.yml`** — `cargo`, `github-actions`, and `docker`, weekly, grouped,
  7-day cooldown.

- **`chart` job** — `make chart-lint`: `helm lint --strict` and `kubeconform` over what the
  chart renders for each value set in `charts/apigw/ci/`. `azure/setup-helm` installs a pinned
  helm version; kubeconform is downloaded at a pinned version and checked against a pinned
  checksum.

When adding a workflow, keep `--locked` on every cargo invocation, `persist-credentials: false`
on checkout, and relock with `gh actions-lock` after adding an action.

## Releases

Versions are calendar versions, `vYYYY.M.N`: the Nth release of that month. One version names
the binary, the packages, the image, and the chart.

To release:

1. Open a pull request that sets `[workspace.package] version` in `Cargo.toml` (and
   `Cargo.lock`), titled `chore: bump version to 2026.11.1`, and merge it.
2. Optional, and worth doing after any change to the build: run the **Release** workflow by
   hand (`workflow_dispatch`) on `main`. That is a dry run: it builds and tests everything as
   version `0.0.0-<sha>` and publishes nothing.
3. Push the tag from the merged commit: `git tag -a v2026.11.1 -m v2026.11.1 && git push origin v2026.11.1`.

`.github/workflows/release.yml` then runs:

| Job | Does |
|---|---|
| `gates` | Fails unless the tag is a calendar version equal to the `apigw` crate version. Then fmt, clippy, tests, the parity replay, the crypto gates, `cargo-deny`, and the release notes: the commits since the previous tag, grouped by type with git-cliff (`cliff.toml`). There is no `CHANGELOG.md`. |
| `build` | Calls `reusable-build.yml` (below). |
| `publish` | Verifies each artifact's checksum, writes `SHA256SUMS`, and creates the GitHub release with every asset in one call. Releases are immutable, so nothing can be added later. |
| `publish-packages` | Copies the `.rpm` and `.deb` files into `smoketurner/packages`, regenerates and signs the YUM and APT metadata, and pushes with a deploy key. That repository's own workflow syncs it to the bucket behind `packages.smoketurner.com`. If another project pushed first, the job starts again from the new commit, up to three times. |

`.github/workflows/reusable-build.yml` builds each artifact once, and later jobs only repackage
that binary:

| Job | Produces |
|---|---|
| `binaries` | Static musl binaries for x86_64 and aarch64 on native runners, built in Docker (`Dockerfile.build`, `docker-bake.hcl`) with `SOURCE_DATE_EPOCH` set to the commit time, each with a CycloneDX SBOM and a deterministic `tar.gz`. |
| `linux-packages` | The `.rpm` (GPG-signed) and `.deb` from `packaging/nfpm.yaml`. Each is installed in a clean AlmaLinux or Debian container (`packaging/test-install.sh`) before it is uploaded. |
| `image`, `image-index` | `Dockerfile.release` copies the binary onto distroless; one image per architecture is pushed by digest, then joined under the version tag. There is no `latest` tag. |
| `chart` | Writes the image index digest into the chart's `image.digest`, packages it at the release version, and pushes it to `oci://ghcr.io/smoketurner/charts`. |

Every artifact has a build provenance attestation (`actions/attest`) naming the reusable
workflow as its builder, which holds no `contents: write`. Verify one with:

```bash
gh attestation verify apigw-<version>-<target>.tar.gz --owner smoketurner \
  --signer-workflow smoketurner/amazon-apigateway-self-hosted/.github/workflows/reusable-build.yml
gh attestation verify oci://ghcr.io/smoketurner/amazon-apigateway-self-hosted:<version> --owner smoketurner \
  --signer-workflow smoketurner/amazon-apigateway-self-hosted/.github/workflows/reusable-build.yml
```

The release depends on configuration outside this repository:

- Secrets `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the `packages.smoketurner.com` signing key)
  and `PACKAGES_DEPLOY_KEY` (write access to `smoketurner/packages`), all set by
  `smoketurner-infra`.
- Immutable releases enabled in the repository settings.
- The GHCR packages for the image and the chart set to public after the first release.

To try the build locally: `make binary` builds the static binary for
`TARGET` (default `x86_64-unknown-linux-musl`), and `make chart-lint` checks the chart.
