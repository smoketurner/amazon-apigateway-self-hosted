# aws-rolesanywhere-credentials

AWS credentials from [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)
for `aws-config` and the AWS SDK for Rust, signed in process from an X.509 certificate.

AWS ships the Roles Anywhere exchange as a separate program, `aws_signing_helper`, which the SDK
runs through `credential_process`. This crate signs the `CreateSession` request with the
certificate's private key itself, so no helper binary, shell, or C library needs to be installed
next to the application.

```rust
use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_rolesanywhere_credentials::RolesAnywhereCredentialsProvider;

let provider = RolesAnywhereCredentialsProvider::builder()
    .certificate_path("/etc/rolesanywhere/tls.crt")
    .private_key_path("/etc/rolesanywhere/tls.key")
    .trust_anchor_arn("arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/a1b2".parse()?)
    .profile_arn("arn:aws:rolesanywhere:us-east-1:111122223333:profile/c3d4".parse()?)
    .role_arn("arn:aws:iam::111122223333:role/gateway")
    .session_duration(Duration::from_hours(1))
    .build()?;

let config = aws_config::defaults(BehaviorVersion::latest())
    .credentials_provider(provider)
    .load()
    .await;
```

- The certificate file holds the end-entity certificate first, then any intermediates (as
  cert-manager writes `tls.crt`). Keys are unencrypted PKCS#8, PKCS#1, or SEC1; RSA, P-256,
  P-384, and P-521 are supported.
- Both files are read on every refresh, so a renewed certificate is picked up without a restart.
- HTTP goes through the SDK's client stack. `Builder::configure` takes the HTTP client, retry
  configuration, and time source from an `SdkConfig`; otherwise the `default-https-client` and
  `rt-tokio` features supply the defaults.

Signatures use aws-lc-rs, except P-384, which uses RustCrypto's `p384` because aws-lc-rs cannot
sign a SHA-256 digest with a P-384 key ([docs/crypto.md](../../docs/crypto.md#iam-roles-anywhere-signatures)).

## Tests

```bash
cargo test -p aws-rolesanywhere-credentials
```

`tests/fixtures/signing-helper.json` holds requests signed by AWS's own credential helper,
recorded by [`tools/rolesanywhere-oracle`](../../tools/rolesanywhere-oracle). The oracle tests
rebuild each canonical request and verify the helper's signature against it. No test calls AWS.
