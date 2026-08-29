# Changelog

## 0.4.0

### Three editors decided what runs, and nobody was looking

`vscode` covered one editor. JetBrains launches shared startup tasks the moment
a project is opened, and runs File Watchers whenever a matching file changes.
Emacs evaluates Lisp from `.dir-locals.el` when a file in the directory is
visited. Vim reads a project-local rc from the working directory.

Four rules cover them. `jetbrains/startup-task` follows the task to the run
configuration it names, so the report shows the script that runs rather than
only what somebody called it. `jetbrains/file-watcher` is deferred: it needs a
file to change, which is a deliberate act, and one nobody thinks of as running
anything. `emacs/directory-local-eval` reports only the `eval` entry, because
setting `fill-column` is what that file is for and reporting it would fire on
the ordinary use. `vim/project-rc` is a note: Vim reads it only with `exrc`
enabled, which is off by default and is not something the repository controls.

`.idea` files are XML, so they get the same promise the JSON ones already had —
one that does not parse is reported, never passed over. That is one new
dependency, `roxmltree`, which brings nothing of its own.

### What is still not covered, and why that is a decision

Gradle, CMake, Make and Docker build commands, hosted CI workflows, and
instructions in prose stay out. They are real execution paths, and leaving them
out is deliberate.

A `Makefile` runs commands because that is what a `Makefile` is for. Reporting
them would fire on nearly every repository, and a scanner that fires on the
ordinary case teaches people to skip its output — at which point it detects
nothing at all. This project has already narrowed one rule for exactly that:
`vscode/launch-workspace-binary` used to report the `program` of every
`launch.json` ever written.

Prose is harder still. There is no reliable way to tell a `CLAUDE.md` that says
"run the tests" from one that says something worse, without understanding the
text. A keyword rule would fire on almost every repository that works with an
agent, which today is most of them.

The four editor rules are narrow for the same reason they exist: those files
have no purpose other than making something run.

## 0.3.0

### A file it could not read was reported as nothing at all

`Ctx::json` discarded the parse error, and every scanner treated the result the
same way it treated a missing file. Those are not the same thing. A
`.vscode/tasks.json` that opened with a UTF-8 byte order mark — which editors on
Windows write routinely and VS Code reads without complaint — parsed nowhere,
was skipped in silence, and left a repository with a `folderOpen` task fetching
a shell script reporting `nothing executes on open`, exit `0`.

Three bytes were enough. So were UTF-16, a single quote, a binary file, and
JSON nested past the parser's depth limit.

Reading now splits on a different question: does the tool that will actually
open this repository read the file? Where it does, so does onopen — BOM and
UTF-16 are decoded and their contents scanned. Where nobody can, the file is
reported as `unreadable`, with the reason, in the human report, in `--json` and
in SARIF. It is never counted as clean and never omitted. `--quiet` does not
hide it, and neither does an otherwise clean report.

An incomplete scan exits `2`. `--no-fail` still turns findings into `0`,
because that is what it is for; it does not turn an unread configuration file
into `0`, because that is a different claim.

Reading is bounded as well: 8 MiB, regular files only, and a symbolic link that
leaves the repository is reported rather than followed. Following it would let a
repository decide which files on your machine this scanner opens.

### Six scanner families became nine

The rules covered the surfaces that were obvious a year ago. Sixteen new ones
cover the rest: Cursor command hooks and multi-root `*.code-workspace`
automatic tasks, pnpm and Yarn startup code, Python's build and import
surfaces, Cargo build scripts and compiler overrides, direnv, mise and Nix
hooks that fire on entering a directory, and local `pre-commit` entries.

The research behind them, including the vectors deliberately not implemented
and why, is in `docs/RED-TEAM-0.3.0.md`.

### Half the rule set had no test

Eleven of twenty-two rules had no assertion behind them. A rule with no test can
stop firing without anything going red, and a detection that silently stops
firing is indistinguishable from a repository that is clean — the same failure
as the one above, arriving by a slower route.

Every rule now has one, including `git/active-hook` and
`git/hooks-path-redirected`, which had gone untested since the first commit for
a mechanical reason: git will not store a nested `.git`, so their fixtures
cannot be committed and are built at run time instead.

Two more contracts got tests rather than good intentions: the CLI exit codes,
asserted by running the binary, and `--sarif`, checked against the unedited
OASIS schema. That checker deliberately refuses to pass on any schema
construct it cannot evaluate, because a validator that ignores what it does not
understand is this project's own bug wearing a different hat.

### One rule was firing on nearly every repository

`vscode/launch-workspace-binary` reported `"program": "${workspaceFolder}/src/index.js"`
— which is what debugging is, and what almost every `launch.json` ever written
contains. It now reports `runtimeExecutable`, where a repository substitutes the
interpreter itself, and leaves the file being debugged alone. Noise is a defect
here: a scanner that fires on the ordinary case teaches people to skip its
output, and then it detects nothing at all.

An ignore-file line that silences nothing is now reported too. That is how an
ignore file stops working quietly: a rule is renamed or a directory moves, and
what remains reads to the next person as a deliberate decision, covering
something it no longer covers.

### The build checks what the tool argues for

CI compiles against the declared minimum Rust version instead of trusting the
manifest, audits the dependency tree for advisories and licences, and pins every
third-party action by commit digest rather than by a tag that can move. The
README already made this argument about the binary the action downloads; it
applies to the action itself.

A scan of a large real repository runs on every push, with a ceiling, so a
change that makes the walk quadratic fails the build rather than being noticed
later by whoever waits for it.

### Installing no longer means building

`cargo install onopen --locked` works, release archives carry `cargo-binstall`
metadata so the already-built binary can be fetched instead of compiled, and
tagging publishes to crates.io through trusted publishing.

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
