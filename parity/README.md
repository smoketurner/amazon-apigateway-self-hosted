# Parity fixtures

`crates/apigw-parity` compares `apigw` with real API Gateway. `record` sends request cases to
the deployed [reference APIs](../reference/README.md) and stores what came back; `replay`
serves the recorded OpenAPI export with `apigw`, sends the same requests, and diffs the
answers.

```text
parity/
  cases/      request cases (YAML), one or more per file
  fixtures/   <case>.json: the normalized response, and what the echo backend received
  exports/    <api>.json: the OpenAPI export and stage variables the fixtures were recorded against
```

## Replay (offline)

```bash
make parity
# or: cargo build -p apigw -p apigw-parity && ./target/debug/apigw-parity replay
```

For each API that has cases, replay starts `apigw` as a subprocess with `--openapi-file` set to
the recorded export, a freshly generated self-signed certificate, `--base-path /<stage>`, and
the export's stage variables. Integrations that reach the echo Lambda through the
`echo_host` stage variable are re-pointed (through `--integration-overrides`) at an in-process
echo server that reproduces the echo Lambda's output. Replay exits non-zero when a case
differs from its fixture.

Output per case: `PASS`, `FAIL` (with the differing fields), `GAP` (a known gap that still
differs), `STALE` (a known gap that now matches), or `ERROR` (for example a missing fixture).

## Cases

```yaml
cases:
  - name: rest-http-proxy-greedy       # lowercase letters, digits, - and _; also the fixture name
    api: rest                          # rest | http | rest_policy
    method: GET                        # default GET
    path: /http-proxy/a/b              # relative to the stage URL
    query: {x: "1"}
    headers: {x-from-client: abc}
    body: '{"a":1}'
    known_gap: "#19"                   # optional: an issue for a feature apigw lacks
    compare:
      status: true                     # default true
      headers: [content-type]          # response headers to compare, by name
      body: exact                      # exact (default) | json | ignore
      echo:                            # compare what the echo backend received
        fields: [method, path, query]  # default; body is also available
        headers: [x-mapped-header]
```

Only what `compare` selects can fail a replay; everything else is stored for reference.
`known_gap` cases are expected to differ: replay reports them as `GAP`, and as `STALE`
(a failure) once they match, so a marker cannot outlive the fix. Remove `known_gap` when the
issue it names lands.

`{{env:NAME}}` in a path, header, query value, or body is replaced by the environment variable
`NAME`. `record` requires it to be set; `replay` substitutes a placeholder so fixtures never
need real credentials. Every substituted value is redacted from what `record` writes.

## Record (needs the deployed stack)

```bash
terraform -chdir=reference/terraform output -json parity_runner > parity/outputs.json
# download the exports (see .github/workflows/parity.yml for the exact commands)
apigw-parity record --outputs parity/outputs.json --export-dir <downloads> \
  --secret-env PARITY_API_KEY
```

`--export-dir` holds `<api>.openapi.json` from `aws apigateway get-export` (REST,
`--parameters extensions=apigateway,authorizers`) or `aws apigatewayv2 export-api` (HTTP), and
optionally `<api>.stage.json` from `get-stage`; without a stage file the stage variables come
from the Terraform outputs. `record` makes no AWS API calls: it only sends the case requests
to the APIs' public URLs.

Add `--baseline parity --drift-report drift.md` to compare the recording with the committed
fixtures instead of trusting it; the report is written only when something differs. That is
what the nightly workflow does.

## What is normalized

- Volatile response headers (`x-amzn-requestid`, `x-amz-apigw-id`, `apigw-requestid`,
  `x-amzn-trace-id`, `date`, ...) keep their presence but their value becomes `[masked]`;
  connection-level headers (`content-length`, `connection`, `transfer-encoding`, ...) are dropped.
- What the echo received loses the headers the Lambda function URL adds (`host`, `x-forwarded-*`,
  `x-amzn-*`, ...), so only gateway-added differences remain. Its query string is sorted.
- Every distinct IP address in a case becomes `<ip-1>`, `<ip-2>`, ... in order of appearance, so a
  recording made from one client address replays from another.
- JSON bodies compared as `json` ignore key order, whitespace, and per-request keys (`requestId`,
  `time`, `timeEpoch`, ...).
- Redaction removes values passed through `{{env:...}}` and `--secret-env`, JWTs, and 12-digit AWS
  account IDs (`[account-id]`) from fixtures and exports, and the value of any stage variable whose
  name contains `secret`, `token`, or `password`.

## Hand-written fixtures

The checked-in fixtures and exports are marked `"source": "hand_written"`: they were written from
documented API Gateway behavior and the reference stack's definition, not recorded. The first
nightly `record` run compares them with the real APIs and files a drift issue for every difference,
which is how they get confirmed or corrected. Recorded files carry `"source": "recorded"`.

## Not covered yet

- Lambda proxy event shapes. `apigw` can send a Lambda invocation to a plain HTTP endpoint
  (`--lambda-endpoint`), but replay does not start one yet, so cases for `AWS_PROXY` routes can be
  recorded but not replayed.
- Authorizers, API keys, validators, resource policies, mapping templates, and parameter mapping are
  not implemented in `apigw`; the seed cases that exercise them are marked `known_gap`.
- Time-dependent behavior (throttles, quotas, cache TTLs) is covered by property tests, not fixtures.
