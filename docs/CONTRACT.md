# The 1.x contract

Onopen ends up inside other people's automation: a CI job that fails a pull
request on exit `1`, a script that reads `--json`, a code-scanning upload that
reads `--sarif`, the GitHub Action. This page is what those consumers can rely
on for every 1.x release, and what counts as breaking it. A breaking change
means 2.0.0; nothing on this page changes in a minor or patch release.

Every sentence below that a machine could check is checked by a test in
`tests/contract.rs`, `tests/sarif_schema.rs` or `tests/hostile_output.rs`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan completed and nothing runs on its own. Deferred findings and notes do not change this. |
| `1` | The scan completed and found at least one **immediate** execution path. |
| `2` | The answer is incomplete or there is no answer: a configuration file exists and could not be read, the path cannot be scanned, the ignore file is invalid, or the command line is wrong. |

- `2` outranks `1`. Findings plus an unreadable file is `2`: the report is
  partial, and what the unread file would do is unknown.
- `--no-fail` turns `1` into `0`. It never hides `2`. A scan that could not
  read part of a repository has not passed, whatever flag was given.
- The exit code does not depend on the output format. `--json`, `--sarif`,
  `--quiet` and the default view exit the same way on the same tree.
- Findings silenced by an ignore file do not count towards `1`.

## `--json`

The document is described by [`docs/schema/report-v1.json`](schema/report-v1.json)
(JSON Schema draft-07). Its top-level `schema_version` field is `1` for the
whole of 1.x; `version` is the version of onopen that wrote it.

What a consumer can rely on:

- Every field in the schema is present in every document, including on a
  clean scan (empty arrays, zero counts).
- `severity` is one of `immediate`, `deferred`, `note`.
- `rule` is a stable identifier such as `vscode/task-run-on-folder-open`.
- `file` is relative to the scanned root, uses `/` separators, and is the
  exact name on disk. It is not escaped.
- `summary` counts what the arrays carry: `summary.suppressed` is the length of
  `suppressed`, `summary.unreadable` of `unreadable`, and the three severity
  counts partition `findings`. `files_cleared` counts files read that
  contained no execution path.
- `trigger` and `command` have their whitespace collapsed to single spaces and
  are cut to 120 characters (the cut ends in `…`). `reason` is cut to about
  400 characters, keeping the start and the end.
- **Text is data, not display.** Strings carry exactly what the repository
  wrote. JSON itself escapes control characters (`\u001b`), but DEL, C1
  controls and bidirectional overrides travel as ordinary UTF-8. Anything that
  shows a `--json` string to a person has to escape it for its own medium, as
  onopen's own terminal view does. This is deliberate: a consumer that matches
  a command against a list needs the real bytes.

## `--sarif`

SARIF 2.1.0, validated in the test suite against the unedited OASIS schema
(`tests/schema/sarif-2.1.0.json`).

- One run, `tool.driver.name` = `onopen`, `tool.driver.version` = the onopen
  version.
- One `result` per finding, with `ruleId` = the finding's `rule` and `level`
  mapped from severity: `immediate` → `error`, `deferred` → `warning`,
  `note` → `note`.
- Silenced findings are **included**, carrying
  `suppressions: [{ "kind": "external" }]`. They are never dropped.
- A file that could not be read is a result under the rule
  `onopen/unreadable-config`, level `error`.
- Every `ruleId` used by a result is declared in `tool.driver.rules`; only
  the rules this run used are declared.
- `message.text` is what a reviewer reads in code scanning, so repository
  text in it is escaped the way the terminal view escapes it (`\x1b`,
  `\u{202e}`). No escape sequence or bidi override reaches a reviewer raw.
- `artifactLocation.uri` is the path relative to the scanned root, with `/`
  separators, **percent-encoded**: every byte that RFC 3986 does not allow raw
  in a path is written as `%XX`. Kept as they are: `A-Z a-z 0-9 - . _ ~`,
  `! $ & ' ( ) * + , ; =`, `@` and `/`; `:` is always encoded. Decoding it
  gives back the exact name on disk, and a path made only of the kept
  characters is byte for byte what 0.5.x wrote, so existing code scanning
  alerts keep their file. Until 1.0.0 it was written raw, which let a `#`,
  `?`, `:`, space or non-ASCII name produce an invalid or misleading URI.

## Terminal output

The default view is for people and is **not** part of the contract: layout,
wording, colours and ordering may change in any release. Two properties of it
are guaranteed, because they are security properties rather than layout:

- Text from the repository is shown with control characters, escape
  sequences, bidirectional controls and invisible characters made visible
  (`\x1b`, `\u{202e}`, `\u{200b}`), never interpreted by the terminal. The same
  applies to error messages on stderr.
- Silenced findings are always counted, and unreadable files are always
  listed.

Colour is off when stdout is not a terminal or `NO_COLOR` is set.

## What is and is not a breaking change in 1.x

Breaking — only in 2.0.0:

- Removing or renaming a JSON field, or changing its type.
- Changing what an exit code means, or which situations produce it.
- Renaming or removing a rule id, or changing a SARIF level mapping.
- Dropping silenced findings or unreadable files from any machine format.
- Removing or renaming a command-line flag, or changing what it does.
- Changing `schema_version`.

Not breaking — may happen in any 1.x release:

- New JSON fields, new SARIF properties, new top-level sections. Consumers
  must ignore what they do not recognise; the published schema is open to
  added fields for exactly this reason.
- New rules and new scanners. A repository that was clean may produce a
  finding after an upgrade: finding more is the tool's job. Pin a version if
  a pipeline needs identical results.
- Moving an existing finding to a different severity when the old one was
  wrong. This is a fix, and it is always listed in the CHANGELOG.
- The wording of `note`, `reason`, `message.text`, rule descriptions and
  everything in the terminal view.
- The order of findings, of results and of object keys.
- New command-line flags.
