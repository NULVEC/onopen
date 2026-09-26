# Red-team audit 1.0.0

0.3.0 and 0.5.0 asked whether a hostile repository could make onopen report
clean. This pass asked the other questions a 1.0 has to answer: can the
repository attack the person reading the report, the filesystem the scanner
walks, the parsers' appetite, or the release the user downloads — and can
onopen be trusted not to send anything anywhere. Each attack below has a test;
the file is named next to it.

## Output aimed at the reader (`tests/hostile_output.rs`)

| Attack | Before | Now |
|---|---|---|
| OSC 52 in a task command (writes the clipboard) | Printed raw: the terminal executed it | Shown as `\x1b]52;…\x07` |
| CSI erase-line + carriage return | Could paint over the finding | Escaped; CR was already flattened to a space |
| OSC 8 hyperlink | Rendered as a clickable link | Escaped |
| Single-byte C1 CSI (`U+009B`) | Raw | `\u{9b}` |
| Right-to-left override / isolates ("Trojan Source") in a command or path | Reordered what the reader saw | `\u{202e}` etc. |
| Zero-width, soft hyphen, BOM, tag characters | Invisible | Escaped |
| Escape sequence in an ignore-file error on stderr | Raw | Escaped |

`src/visible.rs` is applied to the terminal view, stderr and SARIF
`message.text`. **Decision:** `--json` keeps exact data. serde escapes C0
controls; DEL, C1 and bidi travel as UTF-8, and whoever displays a JSON string
escapes it for their own medium. SARIF `artifactLocation.uri` is
percent-encoded (1.0.0), so bidi and `#`/`?`/`:` in a path cannot change what
it shows or means. A literal backslash is not escaped, so Windows commands stay
readable: a repository that writes the four characters `\x1b` looks the same as
an escaped ESC, but nothing is interpreted. Accepted limit.

## Filesystem (`tests/filesystem.rs`)

| Attack | Before | Now |
|---|---|---|
| `.vscode` symlink / Windows junction pointing outside the root | `tasks.json` outside was read and reported as the repository's | Canonical path must stay under the canonical root; otherwise unreadable (exit `2`) |
| `.onopenignore` as a FIFO, a link to `/dev/zero`, or a link outside | Hung, never ended, or parsed the outside file | Regular files inside the root only, 8 MiB cap during the read; error, exit `2` |
| Symlinked git hooks, `conftest.py`, `.pth` inside the repository | Skipped by walkers | Reported |
| FIFO or device as a config file (Unix) | — | Not a regular file: unreadable |
| Non-UTF-8 file names (Unix) | Lost by walkers | Read by their real path |
| Windows device names (`CON`, `NUL`) as repository files | — | Not regular / not canonicalisable: never read |
| Alternate data streams (`tasks.json:evil`) | — | Not applicable: scanners read fixed names and directory listings do not return streams |
| Paths longer than 260 characters | — | std adds the `\\?\` prefix; tested |

Seven of the eleven Windows tests failed against 0.5.2.

Limit: walkers inside `.devcontainer/` still resolve by relative name, so a
non-UTF-8 subdirectory there would be reported absent rather than unreadable.

## Resource exhaustion (`tests/exhaustion.rs`, 1 MiB stack)

| Attack | Before | Now |
|---|---|---|
| YAML "billion laughs" (aliases) | Expanded; nine levels exhausted memory | Counted with alias weight; > 100,000 nodes refused |
| ~1,000 nested XML elements | Stack overflow abort, no report, no exit `2` | Lexical depth pass; > 256 levels refused |
| Deep JSON / TOML / flow YAML | Already bounded by the parsers | Covered by tests |
| TOML error quoting a 200 KB line | Whole line in the report | Reasons cut to 400 characters, start and end kept |
| 7 MiB task label | Printed whole | Triggers cut to 120 characters |
| One enormous line under the 8 MiB limit | — | Read normally |

`fuzz/fuzz_targets/configs.rs` covers JSONC, YAML, XML and the ignore-file
parser, next to the existing `gitindex` target. cargo-fuzz was not available
during this pass; the targets compile (`cargo check --bins` in `fuzz/`).

## No data leaves the machine (`tests/privacy.rs`, `deny.toml`)

- `deny.toml` bans 30 crates by name: HTTP clients and servers, WebSocket,
  TLS, DNS, raw sockets, async runtimes and telemetry. Checked by adding
  `ureq`: `cargo deny check bans` failed on `ureq` and `rustls`.
- The only environment variable read is `NO_COLOR`. The global Git
  configuration is not read.
- A scan in every output mode leaves the scanned tree and the working
  directory identical, including modification times.

## The release itself

- The Action verifies `SHA256SUMS` **and** the Sigstore attestation, bound to
  this repository's `release.yml` and the requested tag. Checked against the
  real v0.5.2 release (passes) and with a wrong signer workflow (fails).
- CycloneDX SBOM attached and attested; builds use `--locked`,
  `SOURCE_DATE_EPOCH` and path remapping. Two Windows builds in different
  directories were byte-identical. Linux and macOS reproducibility could not be
  checked locally.
- OpenSSF Scorecard workflow; every workflow runs with least-privilege
  `permissions:` and actions pinned by SHA.

## What was deliberately not applied

Obfuscation, anti-tamper, debugger/VM/sandbox detection, EDR hooks,
licensing, vaults and IAM from our internal security library were considered
and rejected:

- Onopen is open source under Apache-2.0. Obfuscating a binary whose source is
  public protects nothing and breaks reproducible builds, which are worth more.
- A security tool that detects debuggers or virtual machines behaves like
  malware. Antivirus products would flag it, and trust is the product.
- Binary integrity already comes from something stronger than a home-made
  signature: Sigstore provenance tied to the workflow and tag, plus checksums
  and an attested SBOM.

## Verification

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo deny check
cargo fuzz run configs -- -max_total_time=60
cargo fuzz run gitindex -- -max_total_time=60
```
