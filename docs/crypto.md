# Crypto & TLS: aws-lc-rs only

apigw uses **aws-lc-rs** as the single crypto provider, everywhere — for the TLS listeners,
outbound HTTPS to integrations, the AWS SDK's HTTPS client, and the OTLP exporters. OpenSSL and `ring` are deliberately kept out: they're
banned in `deny.toml` and excluded by feature selection.

Why: one audited, FIPS-capable provider; no system OpenSSL to cross-compile or patch; a
smaller attack surface; and no ambiguity about which backend rustls picks at runtime.

## Install the default provider once, at startup

rustls requires a process-wide default `CryptoProvider`. Install aws-lc-rs as the very first
thing in `main`, before any TLS connection or HTTP client is created:

```rust
fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("default crypto provider already installed"))?;

    // ... build runtime, clients, listeners ...
    Ok(())
}
```

`install_default` returns `Err` if a provider is already set, so the `map_err` keeps the
strict `unwrap_used`/`expect_used` lints satisfied. When you need an explicit config (e.g. a
custom `ClientConfig`), build it from the provider directly:

```rust
let config = rustls::ClientConfig::builder_with_provider(
        std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .with_safe_default_protocol_versions()?
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

## Feature selection

Enable the aws-lc-rs path on every TLS-using crate, with default features off so no other
backend sneaks in:

```toml
rustls       = { workspace = true, features = ["aws-lc-rs", "std", "tls12", "prefer-post-quantum"] }
tokio-rustls = { workspace = true, features = ["aws-lc-rs", "tls12"] }
reqwest      = { workspace = true, features = ["rustls", "http2", "stream"] }  # rustls = aws-lc-rs in 0.13
aws-sdk-*    = { workspace = true, features = ["default-https-client", ...] }  # not the legacy `rustls` feature
rcgen        = { workspace = true, features = ["aws_lc_rs", "pem"] }           # dev-dependency
opentelemetry-otlp = { workspace = true, features = ["reqwest-blocking-client", "grpc-tonic", "tls-aws-lc", "tls-roots", ...] }
```

Never enable `native-tls`, `default-tls`, a `ring` feature (`tls-ring` on `opentelemetry-otlp`), or the AWS SDK's
`rustls`/`legacy-https-client` features (they pull hyper 0.14 with `ring`).

## Keys exported from ACM

With `--domain-cert-source acm`, ACM's `ExportCertificate` returns the private key as an encrypted
PKCS #8 `EncryptedPrivateKeyInfo` (RFC 5958). `domain/encrypted_key.rs` decrypts it with aws-lc-rs
alone (`pbkdf2` and `cipher`), so no PKCS #8 or PBES2 crate joins the graph:

- **Accepted:** PBES2 with PBKDF2 (HMAC-SHA1, SHA-256, SHA-384 or SHA-512) and AES-128/192/256-CBC.
  PBES1, scrypt, other PRFs and other ciphers are refused, not guessed at.
- **Checked:** the iteration count (1 to 10,000,000), a `keyLength` that matches the cipher, a
  16-byte IV, no trailing data, and that the plaintext is a single DER SEQUENCE, which catches a
  wrong passphrase that still unpads.
- **Run off the async runtime:** decryption runs on a blocking thread (`spawn_blocking`), because
  the maximum iteration count takes seconds.
- **Zeroized:** the passphrase, the derived key and the ciphertext buffer. rustls's
  `PrivatePkcs8KeyDer` and the AWS SDK's request buffers are not, so copies of the key and the
  passphrase can stay in memory until the allocator reuses it.

## Enforce it

`deny.toml` already denies `openssl`, `openssl-sys`, `native-tls`, and `ring`, so a stray
feature fails `cargo deny check`. Double-check the resolved graph after wiring up TLS:

```bash
cargo tree --target all -i ring          # expect: "nothing to print" (locked as an unused optional dependency)
cargo tree --target all -i openssl-sys   # expect: "did not match any packages"
cargo tree --target all -i aws-lc-rs     # expect: aws-lc-rs present, pulled by rustls
```

Both answers for `ring` and `openssl-sys` mean the crate is not built. `ring` stays in
`Cargo.lock` because `rustls-webpki` and `quinn-proto` list it as an optional dependency; the
release gate therefore looks at what the command prints, not at its exit status.

An empty result for `ring`/`openssl-sys` and a present `aws-lc-rs` confirms the single-
provider setup. Make `cargo deny check` part of CI (it already is) so regressions are caught
on every PR.
