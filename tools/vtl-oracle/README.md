# VTL oracle

Renders mapping templates with the real engine API Gateway is built on, Apache Velocity 1.7,
and Jayway JsonPath, so `apigw-vtl` can be compared against them. Nothing here calls AWS.

`VtlOracle.java` stubs `$input`, `$util`, `$context`, and `$stageVariables` the way the gateway
documents them, runs each template through Velocity with `directive.foreach.maxloops=1000`, and
records the output and the `$context` map after rendering. The jars are fetched by Maven
coordinate and checked against pinned SHA-256 sums in the `Dockerfile`, on a JDK image pinned by
digest. The run itself has no network access.

```bash
tools/vtl-oracle/run.sh            # rewrites cases/*.expected.jsonl
cargo test -p apigw-vtl --test oracle
```

## Corpus

Every `cases/*.json` file is an array of `{"name", "template"}` objects. A case may also set
`bodyJson` (or a raw `body`), `params`, `context`, and `stageVariables`; anything it leaves out
comes from `cases/defaults.json`. `run.sh` writes the matching `*.expected.jsonl`, one line per
case: `{"name", "output", "context"}`, or `{"name", "error"}` when Velocity threw.

| File | Contents | Source |
|---|---|---|
| `language.json` | whitespace, escapes, `#set`, `#if`, `#foreach`, comments, parse errors | hand-written |
| `builtins.json` | `$input`, `$util`, `$context`, and the String, List, and Map methods | hand-written |
| `jsonpath.json` | JSON path syntax, filters, functions, and Jayway's quirks | hand-written |
| `gateway-templates.json` | templates in the shape real APIs use: DynamoDB, SQS, Lambda wrappers, error mapping, response overrides | hand-written |
| `operators.json` | every arithmetic and comparison operator over 23 operand types | `generate.py operators` |
| `whitespace.json` | directive and reference placement against spaces, tabs, and line endings | `generate.py whitespace` |
| `random.json` | 1,500 random nestings of directives, references, and text | `generate.py random 1 1500` |

`generate.py` is deterministic: the same arguments always produce the same file, so the
workflow regenerates the generated files and fails on any diff.

## Known divergences

`KNOWN_DIVERGENCES` in `crates/apigw-vtl/tests/oracle.rs` lists the corpus cases that still
differ, each with its reason. A listed case must keep differing; one that starts matching fails
the test so the list cannot go stale.

## Scheduled run

`.github/workflows/vtl-oracle.yml` runs weekly. It re-renders the corpus and fails if the
recorded expectations drifted, replays 3,000 fresh random templates (seeded with the run
number, so a failing seed is reproducible with `generate.py random SEED 3000`), and fuzzes the
`render`, `json_path`, and `java_regex` targets for five minutes each.

## Live checks against API Gateway (not done yet)

Velocity is the engine, but API Gateway wraps it: the `$input`, `$util`, and `$context` objects
are AWS's own, and their details can only be confirmed against the service. Those details are
stubs here, so each is a guess that `TestInvokeMethod` should settle once the reference stack
(`terraform/environments/dev`) is deployed:

| Behavior | What the stub does |
|---|---|
| `$input.json()` serialization | compact output, non-ASCII left unescaped |
| `$input.params(name)` header lookup | case-insensitive |
| `$input.path()` on a scalar | the Java value itself, not JSON |
| `$util.escapeJavaScript` | commons-lang 2 `StringEscapeUtils` |
| `$util.urlEncode` / `urlDecode` | `java.net.URLEncoder` / `URLDecoder` with UTF-8 |
| `$util.base64Decode` | lenient about missing padding |

To check one: create a REST API method with a mock or `AWS` integration whose request template
is the template under test, call `aws apigateway test-invoke-method` with a body, headers, and
stage variables, and compare `log`/`body` with the oracle's output for the same inputs. Each
confirmed behavior then becomes a fixture. No live check has been run, and the oracle never
contacts AWS.
