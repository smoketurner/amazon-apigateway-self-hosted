# rolesanywhere-oracle

Records the IAM Roles Anywhere `CreateSession` requests that AWS's own credential helper,
`aws_signing_helper`, signs, so `crates/aws-rolesanywhere-credentials` can be checked against
them. Nothing here calls AWS.

```bash
tools/rolesanywhere-oracle/run.sh
```

The image builds the helper from
[aws/rolesanywhere-credential-helper](https://github.com/aws/rolesanywhere-credential-helper) at
the commit in `HELPER_COMMIT` (`go install` checks the module against the Go checksum database),
and `oracle/main.go`, which uses only the Go standard library. The run has no network access.
For each case the oracle issues a certificate (through an intermediate for the `-chain` cases),
serves a stand-in Roles Anywhere on `127.0.0.1`, runs
`aws_signing_helper credential-process --endpoint http://127.0.0.1:PORT ...`, and records the
certificate, the private key, and the request the helper sent. The result is
`crates/aws-rolesanywhere-credentials/tests/fixtures/signing-helper.json`; commit it with any
change here.

The crate's `oracle_tests` load the same files, compare the certificate, chain, serial number,
query string, and body with what the helper sent, rebuild the canonical request from the
headers the helper signed, and verify the helper's signature with the certificate's public key.
That signature only verifies if the crate builds the canonical request and string to sign
byte for byte as the helper does.

The keys and certificates are throwaway test material generated on each run.

## Updating the helper

Set `HELPER_COMMIT` in the `Dockerfile` to the new release's full commit SHA (and the Go image
if the release needs a newer Go), run `run.sh`, and review the fixture diff: the requests change
on every run (new keys, dates, and invocation IDs), but their shape should not.
