# apigw-parity

Dev tool that measures `apigw` against real Amazon API Gateway. It is not part of the gateway and
is not shipped.

- `record` sends each request case in `parity/cases` to the reference APIs deployed from
  [`terraform/environments/dev`](../../terraform/README.md) and stores the normalized responses
  in `parity/fixtures` and the APIs' exports in `parity/exports`.
- `replay` starts the `apigw` binary on each recorded export, points its integrations at an
  in-process echo server, sends the same requests over TLS, and diffs the responses against the
  fixtures. It needs no AWS access and runs in CI.

```bash
make parity
# or: cargo build -p apigw -p apigw-parity && ./target/debug/apigw-parity replay
```

`apigw-parity --help` lists the options for each subcommand. [parity/README.md](../../parity/README.md)
covers the case format, fixture layout, and replay output, and
[docs/parity.md](../../docs/parity.md#measuring-parity) explains how the fixtures back the feature
matrix.

## Tests

```bash
cargo test -p apigw-parity
```
