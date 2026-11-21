# Parity fixtures

`crates/apigw-parity` compares `apigw` with real API Gateway. `record` sends request cases to
the deployed [reference APIs](../terraform/README.md) and stores what came back; `replay`
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
differs), `NEW` (a case marked `unrecorded` that has no fixture yet), `STALE` (a known gap that
now matches, or an `unrecorded` case that has a fixture), or `ERROR` (for example a missing
fixture).

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
    unrecorded: true                   # optional: added to the stack, not recorded yet
    compare:
      status: true                     # default true
      headers: [content-type]          # response headers to compare, by name
      body: exact                      # exact (default) | json | ignore
      echo:                            # compare what the echo backend received
        fields: [method, path, query]  # default; also body, resource, path_parameters
        headers: [x-mapped-header]
```

Only what `compare` selects can fail a replay; everything else is stored for reference.
`known_gap` cases are expected to differ: replay reports them as `GAP`, and as `STALE`
(a failure) once they match, so a marker cannot outlive the fix. Remove `known_gap` when the
issue it names lands.

A case for a route or behavior the committed exports do not have yet is added with
`unrecorded: true`: replay reports it as `NEW` instead of failing on the missing fixture.
`record` records it like any other case. Commit the new fixture and export and remove the
marker in the same change; replay fails while a case with a fixture keeps it.

`{{env:NAME}}` in a path, header, query value, or body is replaced by the environment variable
`NAME`. `record` requires it to be set; `replay` substitutes a placeholder so fixtures never
need real credentials. Every substituted value is redacted from what `record` writes.

## Record (needs the deployed stack)

```bash
terraform -chdir=terraform/environments/dev output -json parity_runner > parity/outputs.json
# download the exports (see .github/workflows/parity.yml for the exact commands)
apigw-parity record --outputs parity/outputs.json --export-dir <downloads> \
  --secret-env PARITY_API_KEY
```

`--export-dir` holds `<api>.openapi.json` from `aws apigateway get-export` (REST,
`--parameters '{"extensions":"apigateway,authorizers"}'`; the shorthand form splits the value on
its comma and is rejected) or `aws apigatewayv2 export-api` (HTTP), and
optionally `<api>.stage.json` from `get-stage`; without a stage file the stage variables come
from the Terraform outputs. For the HTTP API, `http.api.json` from `aws apigatewayv2 get-api`
supplies the CORS configuration, which `export-api` leaves out; `record` adds it to the export
as `x-amazon-apigateway-cors`, as `apigw` does when it reads a live API. `record` makes no AWS API calls: it only sends the case requests
to the APIs' public URLs.

Add `--baseline parity --drift-report drift.md` to compare the recording with the committed
fixtures instead of trusting it; the report is written only when something differs. That is
what the manually run `parity.yml` workflow does.

## What is normalized

- Volatile response headers (`x-amzn-requestid`, `x-amz-apigw-id`, `apigw-requestid`,
  `x-amzn-trace-id`, `date`, ...) keep their presence but their value becomes `[masked]`;
  connection-level headers (`content-length`, `connection`, `transfer-encoding`, ...) are dropped.
- What the echo received loses the headers the Lambda function URL adds (`host`, `x-forwarded-*`,
  `x-amzn-*`, ...), so only gateway-added differences remain. Its query string is sorted.
- Every distinct IP address in a case becomes `<ip-1>`, `<ip-2>`, ... in order of appearance, so a
  recording made from one client address replays from another.
- JSON bodies compared as `json` ignore key order and whitespace, and each member that differs is
  reported by its JSON pointer. Members whose values differ per request (`requestId`, `time`,
  `timeEpoch`, `X-Amzn-Trace-Id`, `integrationLatency`, ...) or between a deployed API and a replay
  of its export on localhost (`apiId`, `accountId`, `resourceId`, `domainName`, `Host`,
  `X-Forwarded-Port`, `sourceIp`, `stageVariables`, ...) are masked, but must be present on both
  sides. `deploymentId`, which a replay has no value for, is dropped from both.
- Redaction removes values passed through `{{env:...}}` and `--secret-env`, JWTs, and 12-digit AWS
  account IDs (`[account-id]`) from fixtures and exports, and the value of any stage variable whose
  name contains `secret`, `token`, or `password`. In a JSON response body, the value of every member
  whose key suggests a credential is removed wherever it appears, which covers the stage variables
  an echoed Lambda event repeats.

## What replay stands in for

Replay runs no AWS service. The in-process echo server reproduces the reference stack's two
functions: the echo function (a proxy response carrying the event for proxy events, the event itself
for anything else, and its failures) and the authorizer function (`allow`, `deny`, or an error).
Both sides are called over HTTP/1.1, so header-name case is comparable.

## Recorded fixtures

The checked-in fixtures and exports carry `"source": "recorded"`: they are what the deployed
reference APIs answered. A fixture written by hand from documentation would carry
`"source": "hand_written"`; there are none at present.

## Not covered yet

- AWS service integrations (SQS, DynamoDB, Step Functions, EventBridge) and HTTP API
  integration subtypes, which replay has no stand-in for.
- VPC links, which need the optional internal load balancer and a replay stand-in for it.
- Custom domains and mutual TLS, which need a registered domain, a certificate, and a
  truststore the reference stack does not create.
- Responses that need a credential replay cannot mint (a valid Cognito or JWT token).
- Time-dependent behavior (throttles, quotas, cache TTLs) is covered by property tests, not fixtures.
