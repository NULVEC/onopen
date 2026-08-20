# Changelog

## 0.2.0

The release that makes onopen usable on a repository someone actually has.

### Sub-projects are scanned, not just the root

A monorepo keeps a `package.json` and a `.vscode/` in every workspace, so a
task set to `runOn: folderOpen` one directory down fired the moment somebody
opened that workspace — and onopen called the repository clean. A silent false
negative is the worst failure a scanner has, because it is the outcome the tool
exists to prevent.

Findings now carry the path from the top of the scan, so a workspace hit reads
as `packages/api/.vscode/tasks.json`. Dependency directories — `node_modules`,
`vendor`, `target` and their kin — are never entered, and `.gitignore` is
honoured. `--depth 0` restores the old behaviour.

### Findings can be silenced, but never invisibly

Without this the first false positive is also the last run. An `.onopenignore`
takes `<rule|*>  <path glob|*>` lines with the reason after a `#`.

Silenced findings are kept rather than dropped, counted in the summary, printed
even on a report that is otherwise clean, and readable with
`--show-suppressed`. A scanner that can be told to look away without saying so
is worse than no scanner, because it reports clean with authority. `*  *` is
refused for the same reason: that is not configuration, it is turning the tool
off.

### SARIF, releases and a GitHub Action

`--sarif` emits SARIF 2.1.0, so findings land on the diff in GitHub's Security
tab rather than in log output nobody opens. Silenced findings appear there too,
carrying SARIF's own suppression marker.

Tagging now builds binaries for Linux, macOS on both architectures, and
Windows, with checksums and build provenance attestation. The action downloads
the one matching the runner and verifies its digest before running it.

```yaml
- uses: NULVEC/onopen@v0
```

`fail-on-findings` defaults to true but exists to be turned off: on a
repository that already has findings, a gate that blocks on day one gets the
action deleted, while a report that does not block gets read.

## 0.1.0

First cut. Six scanners — VS Code tasks and settings, agent hooks, MCP server
declarations, package manifests, dev containers, git hooks — reading
configuration and reporting what executes, ranked by whether it runs on its own
or waits for a deliberate act.
