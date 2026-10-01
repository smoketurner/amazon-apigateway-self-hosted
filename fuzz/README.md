# Fuzz targets

A detached crate (its own empty `[workspace]`) so that nightly-only fuzzing never touches the
workspace build. Needs `cargo install cargo-fuzz` and a nightly toolchain.

```bash
cargo +nightly fuzz run render --fuzz-dir fuzz -- -max_total_time=60
cargo +nightly fuzz run json_path --fuzz-dir fuzz -- -max_total_time=60
cargo +nightly fuzz run java_regex --fuzz-dir fuzz -- -max_total_time=60
```

| Target | Exercises |
|---|---|
| `render` | `apigw-vtl`: parse an arbitrary template and render it against an arbitrary body under tight limits |
| `json_path` | `apigw-vtl`: parse an arbitrary JSON path and evaluate it against an arbitrary document |
| `java_regex` | `apigw-regex`: translate an arbitrary pattern and run every operation with a small backtrack limit |

Every target must return normally: errors are fine, panics, hangs, and out-of-memory kills are
not. `corpus/` and `artifacts/` are not committed.
