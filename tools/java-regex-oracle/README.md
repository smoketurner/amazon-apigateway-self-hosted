# java-regex-oracle

Generates the `java.util.regex` fixtures that `crates/apigw-regex` is tested against, by running
real Java.

```bash
tools/java-regex-oracle/run.sh
```

The script runs `Oracle.java` in an `eclipse-temurin` image pinned by digest (JDK 21), with no
network access, and writes `crates/apigw-regex/tests/fixtures/java-regex.jsonl`. Docker is the
only requirement; Java does not need to be installed. Commit the regenerated fixtures together
with any change to `cases.json`.

## Tables

```bash
tools/java-regex-oracle/tables.sh
```

runs `Tables.java` in the same image and writes `crates/apigw-regex/src/tables.rs`: every Unicode
block name `Character.UnicodeBlock.forName` accepts with the block's range, and every script
name `Character.UnicodeScript.forName` accepts. Regenerate it with the fixtures when the JDK
changes.

## Cases

`cases.json` is a list of groups:

```json
{"pattern": "(a)(b)?", "inputs": ["ab", "a"], "replacements": ["$2$1"], "limits": [-1, 2]}
```

For every input the oracle records `matches`, `find` (with groups), `find_all` (every
`Matcher.find` match), `replace_all` and `replace_first` with `<$0>` plus each listed
replacement, and `split` with limit `0` plus each listed limit. Offsets are UTF-16 code unit
indexes, as Java reports them. A pattern Java rejects produces a single `compile` record whose
expected value is the exception class.

## Updating the JDK

Pull the new image, read its digest with `docker inspect --format '{{index .RepoDigests 0}}'`,
update `IMAGE` in `run.sh` and `tables.sh`, regenerate both, and review the diffs.
