# Onopen

**See what runs when you open a repository.**

You clone something, or an agent clones it for you, and you open it. Before you
read a line, a VS Code task can fire, an agent hook can spawn a shell, an MCP
server can `npx` down a package that no lockfile pins.

Onopen answers one question and does nothing else:

> If I open this, what executes on my machine?

```
  onopen  ./unknown-repo

! .vscode/tasks.json               runOn: folderOpen        curl -fsSL https://…/i.sh | sh
! .claude/settings.json            hook SessionStart        node -e "require('https')…"
! .claude/settings.json            mcp server: helper       npx -y unpinned-helper@latest
! .devcontainer/devcontainer.json  initializeCommand        bash -c 'cat ~/.gitconfig | curl…'
! package.json                     preinstall               node -e "eval(Buffer.from(…))"
~ .githooks/pre-commit             hook script: pre-commit  curl -fsSL https://…/stage2 | sh
· package.json                     dependencies: internal   git+https://…/internal-tools.git

  5 execution paths before you type a line · 1 deferred, 1 to note
```

## Why this exists

Dependency scanners read code and versions. A growing share of supply-chain
attacks don't live there — they live in configuration, which nearly every tool
treats as inert data. Config files that carry a shell command are accepted by
VS Code, Cursor, Claude Code, Gemini CLI, npm, Composer and Bundler, and several
of them execute on folder open or on session start, behind a trust prompt most
people click through.

The standard advice for this today is *review your config files by hand, with
the same care as code*. That is not a defence. It is the absence of one.

## Install

Install from crates.io:

```sh
cargo install onopen --locked
```

Release archives for Linux, macOS and Windows are also attached to each
[GitHub release](https://github.com/NULVEC/onopen/releases). To build from a
checkout:

```sh
git clone https://github.com/NULVEC/onopen
cd onopen
cargo build --release
```

The binary lands in `target/release/onopen`.

## Use

```sh
onopen                      # scan the current directory
onopen ./some-repo          # scan a path
onopen --explain            # say why each finding executes
onopen --quiet              # hide files that came back clean
onopen --json               # machine-readable output
onopen --sarif              # SARIF 2.1.0, for GitHub code scanning
onopen --only agents,mcp    # narrow the run
onopen --depth 0            # the root alone, ignoring sub-projects
onopen --show-suppressed    # read what an ignore file silenced
onopen --list-scanners      # what is available
```

## Silencing what you have already read

The first false positive is otherwise also the last run. Put an
`.onopenignore` at the root:

```
# <rule-id | *>   <path glob | *>   # why

npm/install-lifecycle-script  package.json      # reviewed, builds a native module
agent/command-hook            tools/**         # our own bootstrap hooks
*                             vendor/**        # not our code
```

**Silencing is never invisible.** Whatever an ignore file hides is still
counted, and the count is printed even on a report that is otherwise clean:

```
  nothing executes on open.
  2 findings silenced by an ignore file — run with --show-suppressed to read them
```

A scanner that can be told to look away without saying so is worse than no
scanner, because it reports clean with authority. For the same reason
`*  *` is refused: silencing everything is not configuration, it is turning
the tool off, and there is already a way to not run it.

A line that silences nothing is reported too:

```
  ignore file line 4 silenced nothing — the rule id or the path may have moved
```

That line is the quiet way an ignore file stops working. A rule gets renamed or
a directory moves, and what is left reads to the next person as a decision that
was made deliberately, protecting something it no longer covers.

SARIF puts each finding on the line it came from, in the review someone is
already reading, rather than in log output nobody opens. Silenced findings are
included and marked as suppressed rather than dropped, so the machine format
keeps the same promise the human one makes.

**Exit codes.** `0` nothing runs on its own · `1` at least one immediate
execution path · `2` the scan is incomplete or failed. `--no-fail` turns
findings into `0`; it deliberately does not hide an unreadable configuration
file or another scan failure.

## What it reads

| Scanner | Files | Looking for |
|---|---|---|
| `vscode` | `.vscode/*.json`, `*.code-workspace` | automatic tasks, executable settings, terminal env injection, debug prerequisites |
| `agents` | Claude, Gemini and Cursor settings/hooks | command hooks, Cursor environment commands, blanket permission allowlists |
| `mcp` | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, agent settings | servers spawned at session start, `npx`/`uvx` fetch-and-run servers |
| `packages` | npm, pnpm, Yarn, Composer and Bundler config | install hooks, local package-manager code/plugins, build approvals, direct URL dependencies |
| `python` | `setup.py`, `pyproject.toml`, `conftest.py`, `sitecustomize.py` | executable setup files, local build backends and automatic imports |
| `cargo` | `Cargo.toml`, `.cargo/config*` | build scripts, compiler wrappers, runners and linkers |
| `environments` | `.envrc`, `mise.toml`, `.mise.toml`, `shell.nix`, `flake.nix` | directory, lifecycle and development-shell hooks |
| `devcontainer` | `.devcontainer/**/devcontainer.json`, `.devcontainer.json` | `initializeCommand` (runs on the **host**), container lifecycle commands, features |
| `githooks` | Git hook paths and `.pre-commit-config.yaml` | live/checked-in hooks and repository-defined pre-commit commands |

## How findings are ranked

- `!` **immediate** — runs on open, on session start, or on install. No further
  action from you. This is what sets the exit code.
- `~` **deferred** — runs, but only after a deliberate act: installing,
  debugging, committing, building the container.
- `·` **note** — doesn't execute on its own, but widens the surface or removes a
  prompt that would have caught something.

## What it does not do

- **It never executes what it finds.** It reads files and parses them.
- **It never opens a network connection.** No telemetry, no lookups, no updates.
- **It has no accounts, no server, and no paid tier.**

JSONC, TOML and YAML are parsed as their actual formats. UTF-8 BOM and UTF-16
files are decoded. Malformed, binary, oversized and out-of-repository symlinked
configuration is reported as unreadable and exits `2`, never as clean.

## In CI

```yaml
# .github/workflows/onopen.yml
name: onopen
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # so findings reach the Security tab

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: NULVEC/onopen@v0
```

On a repository that already has findings, start with
`fail-on-findings: false`: the report still reaches the Security tab, the
build stays green, and you decide what to silence before turning the gate on.

The action verifies the digest of the binary it downloads before running it.
A tool whose argument is that you should know what you are about to run has no
business skipping that step itself.

## Known limits

Onopen reports *execution paths*, not intent. A `postinstall` that builds a
native module and one that exfiltrates your `.npmrc` both show up; the tool
tells you where to look, it doesn't judge what it finds.

It walks sub-projects as well as the root, because a monorepo hides a
`folderOpen` task one workspace down and reporting only the top directory calls
that repository clean. Dependency directories — `node_modules`, `vendor`,
`target` and their kin — are never entered: what is in them is not the project
you are opening. `--depth 0` restores the root-only behaviour.

It deliberately does not report every command in every build system. It does
not currently inspect JetBrains startup tasks, Emacs/Vim local configuration,
Gradle/CMake/Make/Docker build commands, hosted CI workflows, or instructions
in prose (`CLAUDE.md`, `AGENTS.md`). Those surfaces either need a stronger
trust-boundary model or would turn normal project configuration into noise.

## Contributing

New detections are the most useful contribution, and each one needs both a
hostile fixture and an ordinary clean counterpart. See `tests/v03.rs` for the
compact runtime-fixture pattern.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## License

Apache-2.0. See [LICENSE](LICENSE).

Built by [Veltron](https://veltron.cc).
