# Part 1 — Evasion matrix

The severity labels below describe execution timing, not maliciousness:

- **immediate** — execution follows folder open, agent-session start, or dependency/tool installation without another deliberate act;
- **deferred** — execution requires a deliberate action such as starting a test, debugger, build, task, container, or commit;
- **note** — no direct execution, but a prompt or safety boundary is weakened.

“Prompt” means a product-level confirmation specific to the repository. A generic command such as `npm install` is an action, not a review of every lifecycle hook it triggers.

## A. Versioned files Onopen 0.2.0 does not read

| Evasion | Exact trigger and executor | Confirmation boundary | Severity | Realism and detection decision |
|---|---|---|---|---|
| `.cursor/hooks.json` command hooks | Cursor IDE or a Cursor cloud agent starts a session or reaches a configured hook event and spawns the hook's `command`. Cursor documents repository hooks and lifecycle events including `sessionStart`, `beforeShellExecution`, and `stop`. | Workspace trust and the agent's execution mode are the practical boundary; hooks themselves do not prompt on every invocation. | immediate | **High; detect.** It is the closest modern equivalent to the existing Claude/Gemini hook rule and is a direct 0.2.0 false negative. [Cursor cloud-agent hooks](https://cursor.com/docs/cloud-agent) |
| `*.code-workspace` top-level `tasks` | VS Code opens a multi-root workspace whose workspace document embeds a task with `runOptions.runOn: folderOpen`. VS Code executes it as an automatic task. | Automatic tasks prompt once unless already allowed; they never run in Restricted Mode. Users commonly approve trusted workspaces as a unit. | immediate | **High; detect.** Onopen reads `.vscode/tasks.json` but misses the same schema in a workspace file. [VS Code multi-root tasks](https://code.visualstudio.com/docs/editing/workspaces/multi-root-workspaces), [automatic tasks](https://code.visualstudio.com/docs/debugtest/tasks) |
| `.envrc` | A shell with the direnv hook checks `.envrc` before each prompt and evaluates it in Bash after that exact file has been allowed. Re-entering the directory reloads it. | `direnv allow` is mandatory for a new or changed file. It is a real content-bound prompt, not merely a warning banner. | deferred | **High; detect.** The file is arbitrary shell and is common in development repositories, but the mandatory allow step prevents an `immediate` label. [direnv manual](https://direnv.net/man/direnv.1.html) |
| `mise.toml` / `.mise.toml` hooks | With `mise activate` installed, `hooks.enter` runs when the project is entered, `hooks.cd` on directory changes, and `preinstall`/`postinstall` around `mise install`. Watch-file hooks also run configured commands after matching changes. | Mise has a trust model, but in normal mode commands that execute project behavior can automatically trust active config; paranoid mode is content-bound. | immediate for enter/cd/install hooks; deferred for watch-file hooks | **High; detect structured hooks.** The fields explicitly contain commands and are documented as automatic. [mise hooks](https://mise.jdx.dev/hooks.html), [mise trust](https://mise.jdx.dev/cli/trust.html) |
| `.pnpmfile.cjs` / `.pnpmfile.mjs` | pnpm loads repository JavaScript hooks while reading packages, resolving dependencies, updating config, importing packages, packing, and publishing. `readPackage`, `updateConfig`, `preResolution`, and `afterAllResolved` run during ordinary installation/resolution. | No per-hook confirmation. The developer deliberately invokes pnpm, but install-time execution then occurs before application code. | immediate | **High; detect.** Presence of a nonempty pnpmfile is sufficient: the file is executable JavaScript loaded by pnpm. [pnpm pnpmfile hooks](https://pnpm.io/pnpmfile) |
| `.yarnrc.yml` `yarnPath` | Any Yarn command in the covered directory replaces the global Yarn binary with the repository path; `.js` is required, other files are spawned. | No repository-specific prompt after the user invokes Yarn. | immediate | **High; detect.** This is a direct “config points at executable” field with excellent precision. [Yarn `yarnPath`](https://yarnpkg.com/configuration/yarnrc/) |
| `.yarnrc.yml` local `plugins[].path` | Yarn loads the JavaScript plugin declared by the repository when Yarn starts. | No per-plugin prompt. | immediate | **High; detect local paths.** Registry/bundled plugin references should not be guessed; only a repository-relative plugin path is a direct local execution route. [Yarn configuration](https://yarnpkg.com/configuration/yarnrc/) |
| `pnpm-workspace.yaml` `allowBuilds` / `dangerouslyAllowAllBuilds` | pnpm permits selected dependency lifecycle/build scripts, or all of them, during install. | The setting is the approval; there is no prompt for every dependency script. | note | **Medium; detect.** It does not identify a command, but it removes pnpm's dependency-script boundary. The current pnpm settings reference groups both under build settings. [pnpm settings](https://pnpm.io/settings) |
| `setup.py` | Legacy and setuptools-backed Python builds evaluate repository Python during build/install; pip is also a build frontend. | No per-statement prompt after `pip install .` or a frontend build. | immediate | **High; detect.** The entire file is executable configuration. A clean fixture is absence, not a “safe-looking” `setup.py`. [Python packaging flow](https://packaging.python.org/en/latest/flow/), [modernizing setup.py](https://packaging.python.org/en/latest/guides/modernize-setup-py-project/) |
| `pyproject.toml` local `build-backend` plus `backend-path` | The build frontend adds `backend-path` directories and imports/calls the selected backend during build or install. | No per-backend prompt after installation begins. | immediate | **High; detect only local backends.** Merely naming `setuptools.build_meta`, Hatchling, or another published backend is ordinary metadata; a local backend path is the precise repository-code boundary. [pyproject build systems](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/), [packaging flow](https://packaging.python.org/en/latest/flow/) |
| `conftest.py` | pytest imports discovered `conftest.py` plugins during collection, before tests run. Top-level Python executes on import. | The developer deliberately invokes pytest; there is no prompt for conftest imports. | deferred | **High; detect.** A nonempty file is an execution path, though not an on-open one. Nested files matter because pytest discovers them by tree scope. |
| `sitecustomize.py` | A normal Python startup imports `sitecustomize` from the effective import path after site initialization. A repository root on `sys.path` can therefore run it when Python starts there. | No prompt; starting Python is deliberate. `-S` or isolated/safe-path modes can prevent the route. | deferred | **Medium; detect with a precise note.** This is real interpreter behavior but environment-dependent, so the report must not claim it always fires. [Python `site` documentation](https://docs.python.org/3/library/site.html) |
| `build.rs` or `package.build` in `Cargo.toml` | Cargo compiles and executes the package build script just before building the package. `package.build` may rename it. | No script-specific prompt after the developer starts a Cargo build. | deferred | **High; detect.** Cargo explicitly documents that build scripts may perform arbitrary work. [Cargo build scripts](https://doc.rust-lang.org/stable/cargo/reference/build-scripts.html) |
| `.cargo/config.toml` / `.cargo/config` compiler and runner fields | `build.rustc`, `build.rustc-wrapper`, `build.rustc-workspace-wrapper`, `build.rustdoc`, target `runner`, and target `linker` replace or wrap processes Cargo starts. | No prompt after a build/run begins. | deferred | **High; detect.** These are exact executable fields. Do not flag harmless keys such as `target-dir` or `rustflags`. [Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html) |
| `shell.nix` / `flake.nix` `shellHook` | `nix-shell` or `nix develop` evaluates the development-shell expression and executes its shell hook when entering the environment. | The Nix command is deliberate; modern flakes may warn about untrusted settings but shell code itself is the requested environment. | deferred | **Medium-high; detect `shellHook`.** Do not report an arbitrary Nix file merely because Nix is a programming language. [Nix declarative shells](https://nix.dev/tutorials/first-steps/declarative-shell), [Nix flakes](https://nix.dev/concepts/flakes.html) |
| `.pre-commit-config.yaml` `entry` | After the user installs pre-commit's Git hook, committing causes configured local/system entries to execute. Remote-language hooks may also create environments and run downloaded code. | Installing the hook and then committing are deliberate; each later commit does not re-review the config. | deferred | **High; detect local/system entries.** Remote hooks are supply-chain inputs but reporting every normal pre-commit repository would be noisy; prioritize `repo: local` and `language: system` command entries. |
| `.idea` startup tasks and enabled file watchers | JetBrains can launch shared run/debug configurations on project start. Enabled File Watchers execute configured programs on matching file changes/save. | Project trust/safe mode is the main boundary; plugin availability affects file watchers. | immediate for startup tasks; deferred for save watchers | **Medium; defer implementation.** The behavior is real and shared run configurations are versionable, but JetBrains' internal XML links between startup task IDs and run configurations are not a stable public schema. A substring rule would be noisy. [JetBrains startup tasks](https://www.jetbrains.com/help/idea/settings-tools-startup-tasks.html) |
| `.dir-locals.el` and file-local `eval:` | Emacs applies directory-local variables when visiting a file; `eval:` can evaluate Lisp. | Unsafe variables and `eval:` prompt by default; users can mark values/directories safe or configure unconditional processing. | deferred | **Medium; defer implementation.** Detecting literal `eval` is possible, but execution depends heavily on user safety state. Report only after an Emacs-specific parser and tests exist. [GNU Emacs file-local variables](https://www.gnu.org/software/emacs/manual/html_node/elisp/File-Local-Variables.html) |
| `.vimrc` / `.exrc` in the project | Vim reads a current-directory vimrc only when the nondefault `exrc` option is enabled. Secure mode blocks shell/file/autocommand operations in some ownership cases, but a freshly cloned file is owned by the user. | No prompt once the user has enabled local rc files; secure-mode behavior depends on ownership/config. | immediate | **Low-medium; defer.** Real but opt-in and uncommon. The report would need to state that `exrc` is not enabled by default. [Vim initialization and trojan-horse warning](https://vimhelp.org/starting.txt.html) |
| `.zed/tasks.json` | Zed runs task commands in a login shell when the user selects the task. | Explicit task selection. | deferred | **Medium; do not prioritize.** The path is real but is no more automatic than a Make target, and reporting every task would be expected-noise. [Zed tasks](https://zed.dev/docs/tasks) |
| Gradle `settings.gradle(.kts)` / `build.gradle(.kts)` | Gradle evaluates build logic and plugins during common Gradle operations. | The build is deliberate. | deferred | **High occurrence, low signal; defer.** Treating every Gradle build as a finding would teach users to ignore Onopen. A future rule should target `Exec`, `ProcessBuilder`, or local init/plugin loading with language-aware parsing. |
| CMake, Meson, Make, Just, Taskfile | Configuration/build/task invocations can execute `execute_process`, `run_command`, recipes, or shell tasks. | Explicit configure/build/task invocation. | deferred | **High occurrence, low signal; mostly do not detect.** Only narrowly structured auto/configure-time execution deserves future rules. |
| Dockerfile and Compose commands | Image build executes `RUN`; Compose can execute lifecycle commands when services start. | Explicit image build or `compose up`. | deferred | **High occurrence; do not report every command.** A Dockerfile is intentionally a build program. Onopen should target surprising host execution, not restate that builds run build steps. |
| CI workflows (`pull_request_target`, `workflow_run`, GitLab CI, Jenkinsfile) | A hosted or self-hosted runner executes workflow commands on CI triggers. | Review/merge/event policy, not developer folder open. | out of scope | **Important but do not detect in the core question.** It is remote/runner execution rather than “opening this repository on my machine.” GitHub code scanning and Scorecard already own parts of this space. |
| Agent instructions in `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md` | An agent reads prose and may follow an instruction to run a command, install a dependency, or open a URL. | Tool approvals and sandbox policy vary; users often approve broad plans rather than each instruction. | note to immediate depending on agent policy | **High emerging risk; do not add a keyword rule.** Static string matching cannot reliably separate documentation, quoted attacks, negative instructions, and executable directives. Surface the files in Known limits until a semantic classifier with measurable precision exists. Cursor confirms project rules are version-controlled context. [Cursor rules](https://docs.cursor.com/context/rules), [VS Code agent trust](https://code.visualstudio.com/docs/agents/concepts/trust-and-safety) |

## B. Files 0.2.0 reads, but fields or representations it can miss

| Evasion | Exact trigger and executor | Confirmation boundary | Severity | Realism and detection decision |
|---|---|---|---|---|
| Cursor hooks in a separate supported file | `.cursor/environment.json` is read, but `.cursor/hooks.json` is not. The existing generic hook walker would work if the file were registered. | Same as Cursor hook row above. | immediate | **Very high; fix by adding the file and accepting hooks whose object has `command` even if `type` is omitted by the Cursor schema.** |
| VS Code automatic task in a `.code-workspace` document | The exact `tasks` schema exists at the workspace-document top level, not under `.vscode/tasks.json`. | One-time automatic-task/workspace trust. | immediate | **Very high; add workspace-file discovery and reuse task analysis.** |
| VS Code task command hidden in `dependsOn` | The automatic task has no direct `command`; it depends on another named task that carries the command. 0.2.0 prints `(no command)` and does not resolve the dependency. | Same automatic-task boundary. | immediate | **High; resolve same-document task labels.** Report the dependency chain and resolved commands; unresolved labels remain visible rather than “clean.” |
| VS Code OS-specific command override | A task's `windows`, `linux`, or `osx` object overrides `command`, `args`, and options for that platform. | Same automatic-task boundary. | immediate | **High; merge/report platform overrides.** The current scanner only sees the generic command. |
| MCP process represented by `type: stdio` with nested/alternate server maps | Tools have converged on `mcpServers` and `servers`, but some settings nest them below product-specific sections or use disabled flags. | Modern VS Code prompts for MCP-server trust and re-prompts after config changes. | immediate if enabled; note if remote | **Medium; walk for exact server-map keys, honor `disabled: true`, and say when a product has a server-specific trust prompt.** [VS Code agent trust](https://code.visualstudio.com/docs/agents/concepts/trust-and-safety) |
| Agent command hook without `type: command` | Cursor's hook entries use a `command` field and do not require the Claude/Gemini `type` discriminator. The current recursive collector ignores them. | Agent/session trust boundary. | immediate | **Very high; use file-specific schema.** Do not globally treat every object named `command` as a hook. |
| npm `preprepare` and `postprepare` | npm's install lifecycle includes hooks around `prepare`; 0.2.0 detects `prepare` but not its pre/post companions. | No per-script prompt once install begins. | immediate | **High; add exact lifecycle names.** npm's lifecycle documentation defines the operation order. [npm scripts](https://docs.npmjs.com/cli/using-npm/scripts/) |
| npm `binding.gyp` implicit install script | In the absence of explicit preinstall/install scripts, npm defaults `install` to `node-gyp rebuild` when `binding.gyp` exists. | No per-script prompt once install begins. | immediate | **Do not add as a security finding.** It is expected native-module behavior and the implicit command is npm-owned, not a hidden repository command. It may compile hostile native source, but so can any build. [npm CLI scripts source](https://github.com/npm/cli/blob/latest/docs/lib/content/using-npm/scripts.md) |
| Devcontainer lifecycle command object/array | Lifecycle values can be strings, argv arrays, or objects of parallel commands. | Devcontainer trust/create action. | immediate on host for `initializeCommand`; deferred in container | **Already handled well** by `command_text`; keep hostile fixtures to prevent regression. |
| `Cargo.toml` renamed build script | `[package] build = "tools/bootstrap.rs"` executes the alternate file even if no `build.rs` exists. | Explicit build. | deferred | **High; parse the manifest field, do not only test for `build.rs`.** |
| Relative executable leaves the repository | VS Code, Cargo, Yarn, MCP, and agent command fields may use `../tool`, `${workspaceFolder}/../tool`, environment interpolation, or a symlink to point outside the scan root. | Depends on caller; usually none after trust/action. | same as parent rule | **Report the literal value and annotate escape potential.** Static analysis cannot resolve environment variables reliably; it can reliably identify lexical `..` and absolute paths. |
| Environment interpolation becomes a command | `${env:NAME}`, `${workspaceFolder}`, Yarn `${NAME}`, shell expansion, and tool variables can turn a benign-looking token into a path or command. | Depends on tool. | same as parent rule | **Do not guess the resolved command.** Preserve variables in output. Detect the execution-bearing field; a false literal resolution is worse than an honest unknown. |

## C. Engine evasions

| Evasion | Effect | 0.3.0 requirement |
|---|---|---|
| UTF-8 BOM | `serde_json` rejects a leading BOM although editors commonly accept it, previously making an executable config disappear. | Decode UTF-8 BOM before JSONC parsing and test it end to end. |
| UTF-16 LE/BE | Windows tools can write config as UTF-16; a UTF-8-only reader silently skips it. | Decode BOM-marked UTF-16 LE and BE. Mark odd-length or invalid surrogate input unreadable. |
| Invalid UTF-8 / binary config | `read_to_string().ok()` collapses unreadable into absent. | Carry an explicit unreadable record into human, JSON, and SARIF output and exit with scan-error status. |
| JSONC comment markers inside strings | A naive comment stripper truncates URLs such as `https://...` or command strings containing `/*`. | State-machine parsing must keep comment bytes inside strings and cover escaped quotes. The current implementation already does this; keep tests. |
| Unicode escapes in keys/values | `"co\u006dmand"` can hide a known field from byte-pattern scanners. | Inspect parsed JSON values, never raw-string grep for JSON field names. `serde_json` decoding already satisfies this. |
| Deeply nested JSON | Parser recursion limits or stack exhaustion can turn a hostile file into absence or crash the scanner. | A recursion-limit error is an incomplete scan, not clean. Keep the default parser limit or add an explicit lower bound; never disable recursion limits without an iterative parser. |
| Oversized config | A repository can commit a huge “config” and make the scanner allocate or spend excessive time. | Refuse files above a documented bound (8 MiB is generous for configuration), mark them unreadable, and continue scanning other files. |
| Symlink outside root | A known config path can point at a secret or huge local file outside the repository; following it leaks local content into JSON/SARIF or creates machine-dependent results. | Canonicalize symlinks, refuse targets outside the top scan root, and report them as unreadable. Internal symlinks remain allowed. |
| Symlinked project directory / junction | Project discovery with `follow_links(false)` avoids loops, but marker tests using `exists()` can still observe linked targets. | Treat directory links consistently, never recurse through them, and add platform-gated tests where creation is available. |
| Tracked file hidden by `.gitignore` | Git allows an already tracked file to later match `.gitignore`. The ignore walker can skip a nested project even though its executable config is in the commit. | **Known limit for 0.3.0 unless tracked-file enumeration is implemented without spawning Git.** Do not claim `.gitignore` is a security boundary. Consider a future pure index reader or an opt-in `--include-ignored`. |
| Ignore-file suppression shipped with payload | A commit can add both a command and a matching `.onopenignore` line. The finding is counted but can be absent from the default detailed list and from the failure gate. | Always state suppression counts; include suppressed findings in JSON/SARIF. Add CI guidance that untrusted repositories should be scanned with an explicit empty ignore file. Future versions should distinguish repository policy from reviewer-owned policy. |
| Malformed `.onopenignore` glob | A bad rule could silently fail open or match more than intended. | Reject invalid globs and the universal `*  *` rule. Existing behavior is correct; cover bypass variants with whitespace/comments. |
| Duplicate project discovery | Nested markers can make the same physical file scan twice through overlapping units or symlinks. | Deduplicate canonical config paths or prove units cannot overlap. Deterministic ordering is mandatory for reviewable diffs. |
| Path normalization tricks | `a/../b`, Windows verbatim prefixes, case-insensitive paths, and alternate separators can bypass suppressions or create duplicate identities. | Normalize display paths to `/`, strip Windows verbatim prefixes, reject lexical paths leaving the root, and test Windows case/separator behavior. |
| Parser error reported as success | The most damaging engine behavior is exit `0` after one or more candidate files could not be parsed. | Exit `2` for incomplete scans in normal mode. `--no-fail` should only neutralize findings, not scanner failure. |

## Prioritized backlog

Ranking is by expected harm × real-world frequency × reliable detectability, not by novelty.

| Rank | Vector / engine defect | Priority | Implement in 0.3.0? |
|---:|---|---|---|
| 1 | Unreadable/invalid config silently treated as absent | Critical | Yes |
| 2 | `.cursor/hooks.json` command hooks | Critical | Yes |
| 3 | `*.code-workspace` automatic tasks, including dependencies/platform overrides | Critical | Yes |
| 4 | `.pnpmfile.cjs` / `.pnpmfile.mjs` | Critical | Yes |
| 5 | Yarn `yarnPath` | Critical | Yes |
| 6 | Local Python build backend (`backend-path`) | Critical | Yes |
| 7 | `setup.py` install/build execution | High | Yes |
| 8 | Cargo `build.rs` / renamed build script | High | Yes |
| 9 | Cargo compiler wrappers / runner | High | Yes |
| 10 | Mise automatic/install hooks | High | Yes |
| 11 | Direnv `.envrc` | High | Yes |
| 12 | Yarn local plugins | High | Yes |
| 13 | npm `preprepare` / `postprepare` | High | Yes |
| 14 | pytest `conftest.py` | Medium-high | Yes |
| 15 | Python `sitecustomize.py` | Medium | Yes, with conditional wording |
| 16 | Nix `shellHook` | Medium | Yes |
| 17 | pnpm dependency-build approvals | Medium | Yes, as note |
| 18 | local/system pre-commit entries | Medium | Yes |
| 19 | Tracked configs hidden by `.gitignore` | High but hard | Known limit; future engine work |
| 20 | Agent prose instructions | High but unreliable | No keyword rule |
| 21 | JetBrains startup tasks | Medium and schema-fragile | Research further |
| 22 | Emacs local eval | Medium and state-dependent | Research further |
| 23 | Vim local rc | Low-medium and opt-in | No for 0.3.0 |
| 24 | Every Gradle/CMake/Make/Docker command | High noise | Explicitly no |
| 25 | Hosted CI workflow commands | Different machine/scope | Explicitly no |

The negative list is deliberate. Onopen should not become a catalogue of every build system that can execute code. It should report surprising, configuration-mediated execution paths with a trigger the user can reason about.

# Part 2 — Implementable specifications

## 1. `agent/cursor-command-hook`

- **Scanner:** existing `agents`.
- **Files/structure:** `.cursor/hooks.json`; inspect each entry immediately below `hooks.<event>[]`. A nonempty `command` is executable whether or not `type: command` is present. Ignore entries with `disabled: true` if Cursor supports that field; otherwise do not invent disabled semantics.
- **Severity:** immediate — session/lifecycle hooks can execute as part of opening or starting an agent session, with no per-run hook confirmation.
- **Literal report line:** `.cursor/hooks.json   hook sessionStart   ./scripts/bootstrap.sh`
- **Hostile fixture:** 

  ```json
  {
    "version": 1,
    "hooks": {
      "sessionStart": [
        { "command": "./scripts/bootstrap.sh" }
      ]
    }
  }
  ```

- **Clean fixture:**

  ```json
  { "version": 1, "hooks": {} }
  ```

- **False positives/tightening:** Every reported object is a command hook. Do not recursively match unrelated `command` keys outside `hooks`.

## 2. `vscode/workspace-task-run-on-folder-open`

- **Scanner:** existing `vscode`.
- **Files/structure:** every regular `*.code-workspace` file at the scan-unit root; inspect `tasks.tasks[]` with `runOptions.runOn == "folderOpen"`. Resolve `dependsOn` labels against sibling tasks and merge `windows`/`linux`/`osx` command overrides into the displayed command.
- **Severity:** immediate — VS Code runs it when the trusted workspace opens, after at most the product's one-time automatic-task decision.
- **Literal report line:** `project.code-workspace   runOn: folderOpen (bootstrap)   node ./tools/open.js`
- **Hostile fixture:** 

  ```jsonc
  {
    "folders": [{ "path": "." }],
    "tasks": {
      "version": "2.0.0",
      "tasks": [{
        "label": "bootstrap",
        "type": "shell",
        "command": "node",
        "args": ["./tools/open.js"],
        "runOptions": { "runOn": "folderOpen" }
      }]
    }
  }
  ```

- **Clean fixture:** the same document with `"runOn": "default"`.
- **False positives/tightening:** Require the exact automatic `runOn` value. Ordinary workspace tasks remain unreported.

## 3. `pnpm/pnpmfile-hook`

- **Scanner:** extend `packages` or add `package-managers`; prefer extending `packages` for 0.3.0 compatibility.
- **Files/structure:** `.pnpmfile.cjs` and `.pnpmfile.mjs`; any noncomment, nonwhitespace content. The entire file is code loaded by pnpm.
- **Severity:** immediate — pnpm loads install/resolution hooks after an install command begins.
- **Literal report line:** `.pnpmfile.cjs   pnpm hook module   module.exports = { hooks: { readPackage(pkg) { … } } }`
- **Hostile fixture:** 

  ```javascript
  module.exports = {
    hooks: {
      readPackage(pkg) {
        require("child_process").execSync("node ./stage.js")
        return pkg
      }
    }
  }
  ```

- **Clean fixture:** file absent. A comment-only placeholder may be treated as clean.
- **False positives/tightening:** There is no false positive in saying the module executes; do not claim malicious behavior or a particular hook if static extraction cannot prove it.

## 4. `yarn/yarn-path`

- **Scanner:** `packages`.
- **Files/structure:** `.yarnrc.yml`, scalar `yarnPath` value.
- **Severity:** immediate — the configured repository binary is required/spawned for Yarn commands, including install.
- **Literal report line:** `.yarnrc.yml   yarnPath   ./.yarn/releases/yarn.cjs`
- **Hostile fixture:** `yarnPath: ./tools/yarn-bootstrap.js`
- **Clean fixture:** `nodeLinker: node-modules`
- **False positives/tightening:** None as an execution-path finding. Wording must avoid claiming the checked-in Yarn release is malicious.

## 5. `yarn/local-plugin`

- **Scanner:** `packages`.
- **Files/structure:** `.yarnrc.yml`, each `plugins[]` mapping with a repository-relative `path`. Preserve optional `spec` in the trigger.
- **Severity:** immediate — Yarn loads the local JavaScript plugin when it starts.
- **Literal report line:** `.yarnrc.yml   plugin: audit-tools   ./.yarn/plugins/audit-tools.cjs`
- **Hostile fixture:**

  ```yaml
  plugins:
    - path: ./.yarn/plugins/audit-tools.cjs
      spec: audit-tools
  ```

- **Clean fixture:** `plugins: []`
- **False positives/tightening:** Require a local path; do not treat ordinary scalar settings or remote documentation URLs as plugins.

## 6. `pnpm/dependency-build-approval`

- **Scanner:** `packages`.
- **Files/structure:** `pnpm-workspace.yaml`; `dangerouslyAllowAllBuilds: true` or nonempty `allowBuilds`. Support the legacy `onlyBuiltDependencies` spelling as a compatibility note if encountered.
- **Severity:** note — the setting does not itself run code, but pre-approves dependency build scripts that otherwise would be blocked or reviewed.
- **Literal report line:** `pnpm-workspace.yaml   dangerouslyAllowAllBuilds   true`
- **Hostile fixture:** `dangerouslyAllowAllBuilds: true`
- **Clean fixture:** `dangerouslyAllowAllBuilds: false`
- **False positives/tightening:** Do not report `false`, empty allow maps/lists, or `ignoredBuiltDependencies`.

## 7. `python/setup-script`

- **Scanner:** new `python`.
- **Files/structure:** `setup.py`; any noncomment, nonwhitespace content.
- **Severity:** immediate — supported build/install paths evaluate it after Python installation begins.
- **Literal report line:** `setup.py   Python build/install script   from setuptools import setup`
- **Hostile fixture:**

  ```python
  import subprocess
  subprocess.run(["node", "stage.js"], check=True)
  from setuptools import setup
  setup(name="example")
  ```

- **Clean fixture:** absent. A comment-only file may be clean.
- **False positives/tightening:** Do not call the script malicious; report that it executes. Presence is the precise behavior.

## 8. `python/local-build-backend`

- **Scanner:** `python`.
- **Files/structure:** `pyproject.toml`, `[build-system]` with nonempty `backend-path` and `build-backend`. Report the backend plus paths. Do not report standard external backends without `backend-path`.
- **Severity:** immediate — pip/build imports the repository-local backend during installation/build.
- **Literal report line:** `pyproject.toml   local build backend   backend = local_backend.api; path = ["."]`
- **Hostile fixture:**

  ```toml
  [build-system]
  requires = []
  build-backend = "local_backend.api"
  backend-path = ["."]
  ```

- **Clean fixture:**

  ```toml
  [build-system]
  requires = ["setuptools>=77"]
  build-backend = "setuptools.build_meta"
  ```

- **False positives/tightening:** Requiring `backend-path` avoids flagging every modern Python project.

## 9. `python/pytest-conftest`

- **Scanner:** `python`.
- **Files/structure:** every `conftest.py` within the scan unit, excluding dependency/build directories. Report the first meaningful code line as a preview.
- **Severity:** deferred — imported during pytest collection after the developer explicitly runs tests.
- **Literal report line:** `tests/conftest.py   imported by pytest   import subprocess`
- **Hostile fixture:** `import subprocess; subprocess.run(["node", "stage.js"])`
- **Clean fixture:** absent or comment-only.
- **False positives/tightening:** The finding is intentionally about import execution, not dangerous APIs. Do not elevate to immediate.

## 10. `python/sitecustomize`

- **Scanner:** `python`.
- **Files/structure:** `sitecustomize.py` at a scan-unit root; first meaningful code line as preview.
- **Severity:** deferred — it can run on a normal Python startup from that import path, but starting Python is deliberate and flags/environment can disable site loading.
- **Literal report line:** `sitecustomize.py   imported by Python site initialization   import bootstrap`
- **Hostile fixture:** `__import__("subprocess").run(["node", "stage.js"])`
- **Clean fixture:** absent or comment-only.
- **False positives/tightening:** Limit to the project root rather than every nested same-named module. The note must say “can be imported,” not “always runs.”

## 11. `cargo/build-script`

- **Scanner:** new `cargo`.
- **Files/structure:** `Cargo.toml` `[package].build`. If absent, the conventional `build.rs` at the package root. If `build = false`, do not report. Report renamed paths exactly.
- **Severity:** deferred — Cargo executes the script just before a deliberate build.
- **Literal report line:** `Cargo.toml   package build script   tools/bootstrap.rs`
- **Hostile fixture:**

  ```toml
  [package]
  name = "demo"
  version = "0.1.0"
  build = "tools/bootstrap.rs"
  ```

- **Clean fixture:** same manifest with `build = false` and no `build.rs`.
- **False positives/tightening:** None as an execution path. Do not inspect Rust source to infer intent.

## 12. `cargo/compiler-wrapper`

- **Scanner:** `cargo`.
- **Files/structure:** `.cargo/config.toml` and `.cargo/config`; exact keys `build.rustc`, `build.rustc-wrapper`, `build.rustc-workspace-wrapper`, `build.rustdoc`, `target.<triple>.runner`, and `target.<triple>.linker` when values are nonempty.
- **Severity:** deferred — Cargo spawns the configured executable during build/run after a deliberate Cargo command.
- **Literal report line:** `.cargo/config.toml   build.rustc-wrapper   ./tools/rustc-wrapper`
- **Hostile fixture:**

  ```toml
  [build]
  rustc-wrapper = "./tools/rustc-wrapper"
  ```

- **Clean fixture:**

  ```toml
  [build]
  target-dir = "target"
  ```

- **False positives/tightening:** Match exact semantic keys, not every value containing “rustc” or “runner.”

## 13. `direnv/environment-script`

- **Scanner:** new `environments`.
- **Files/structure:** `.envrc`; any noncomment, nonwhitespace shell content.
- **Severity:** deferred — direnv's content-bound `allow` is a deliberate safety act before first load.
- **Literal report line:** `.envrc   direnv load after allow   source_url https://example.test/env.sh sha256-…`
- **Hostile fixture:** `source_url https://example.test/env.sh sha256-deadbeef`
- **Clean fixture:** absent or comment-only.
- **False positives/tightening:** Do not call exports malicious. The execution route is the Bash evaluation itself, and the note must name the mandatory allow step.

## 14. `mise/automatic-hook`

- **Scanner:** `environments`.
- **Files/structure:** `mise.toml` and `.mise.toml`; `[hooks]` keys `enter`, `cd`, `leave`, `preinstall`, `postinstall`, including inline tables/arrays and `hooks.<name>` tables. Also report `[[watch_files]]` `run`/`task` as deferred, preferably under a separate `mise/watch-file-hook` rule.
- **Severity:** immediate for `enter`/`cd` and install hooks; deferred for `leave` and watch-file hooks. Enter/cd hooks follow directory entry in an activated shell; install hooks follow installation without another act.
- **Literal report line:** `mise.toml   hook enter   ./tools/bootstrap.sh`
- **Hostile fixture:**

  ```toml
  [hooks]
  enter = { run = "./tools/bootstrap.sh" }
  ```

- **Clean fixture:**

  ```toml
  [tools]
  node = "24"
  ```

- **False positives/tightening:** Only exact hook tables/keys. Ordinary tool versions and manually invoked `[tasks]` are not findings.

## 15. `nix/shell-hook`

- **Scanner:** `environments`.
- **Files/structure:** `shell.nix` and `flake.nix`; identify `shellHook =` assignments and capture the first command-bearing line or a bounded expression preview.
- **Severity:** deferred — runs when the developer deliberately enters the Nix development shell.
- **Literal report line:** `shell.nix   shellHook   ./tools/bootstrap.sh`
- **Hostile fixture:**

  ```nix
  { pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    shellHook = ''
      ./tools/bootstrap.sh
    '';
  }
  ```

- **Clean fixture:** the same shell without `shellHook`.
- **False positives/tightening:** Require an assignment token outside a line comment. Do not report every Nix expression.

## 16. `git/pre-commit-local-entry`

- **Scanner:** existing `githooks`.
- **Files/structure:** `.pre-commit-config.yaml`; entries under a `repo: local` block whose hook has nonempty `entry`, or any hook with `language: system`. Report hook `id` and entry.
- **Severity:** deferred — execution requires installing the pre-commit hook and then committing/running pre-commit.
- **Literal report line:** `.pre-commit-config.yaml   local hook: bootstrap   ./tools/bootstrap.sh`
- **Hostile fixture:**

  ```yaml
  repos:
    - repo: local
      hooks:
        - id: bootstrap
          name: bootstrap
          language: system
          entry: ./tools/bootstrap.sh
  ```

- **Clean fixture:** `repos: []`
- **False positives/tightening:** Do not flag every remote pre-commit hook. Local/system is the precise repository-defined command path.

## Engine acceptance criteria

These are release blockers rather than ordinary finding rules:

1. UTF-8 BOM, UTF-16 LE, and UTF-16 BE hostile JSONC fixtures produce the same rule as UTF-8.
2. Invalid text, malformed JSONC, excessive size, broken symlink, and external symlink appear in `unreadable` in JSON and human output.
3. Any unreadable candidate file exits `2`; `--no-fail` does not downgrade scan failure.
4. A deep JSON document returns a controlled incomplete scan rather than panic/stack overflow.
5. Every scanner uses the reporting read helpers; direct `read_to_string(...).ok()` in scanners is forbidden by review/test.
6. Exit codes have subprocess-level tests for clean (`0`), immediate finding (`1`), bad root/unknown scanner/unreadable (`2`), and `--no-fail` (`0` only for findings).
7. Discovery never follows a directory symlink and file reads never follow a symlink outside the top scan root.

# Part 3 — Known limits

## Known limits

Onopen reports execution paths, not intent. A lifecycle script that compiles a native dependency and one that steals credentials receive the same rule and severity. The tool identifies the code-bearing configuration and its trigger; it does not determine whether the code is safe.

A clean report means only that no supported rule matched every supported file that Onopen successfully read. It is not proof that opening, building, testing, or installing the repository is safe.

Onopen is a static reader. It does not execute commands, evaluate shell expansion, import modules, resolve package registries, fetch remote configuration, or open network connections. It therefore cannot know what an environment variable expands to, what a mutable URL serves, what a package's unpublished install script does, or what code a build system generates at runtime.

The scanner covers a deliberately bounded set of configuration-mediated execution routes. It does not report every executable build description. Gradle files, Makefiles, CMake and Meson projects, Dockerfiles, Justfiles, Taskfiles, and ordinary Zed tasks can execute arbitrary commands after a developer invokes them. Reporting all of them would be accurate but unusably noisy.

Agent instruction files such as `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, Cursor project rules, and Copilot instructions can persuade an agent to execute commands. Onopen does not classify natural-language instructions. Keyword matching cannot reliably distinguish an instruction from documentation, a quoted attack sample, or a warning not to run the same command.

Hosted CI execution is outside the core question. GitHub Actions, GitLab CI, Jenkins, and similar systems execute on runners rather than because a developer opened the repository locally. Use workflow-specific security analysis and least-privilege review for those files.

Workspace trust, sandboxing, hook approval, package-manager script policy, and local user configuration affect whether a path actually fires. Onopen reports the configured path and states the relevant boundary where it is known; it cannot read or prove every user's global trust state.

Onopen respects `.gitignore` while discovering subprojects and always excludes dependency/build directories. A file can remain tracked after a later `.gitignore` rule matches it. Until Onopen reads the Git index directly or offers an explicit ignored-file mode, a malicious ignore rule can conceal a nested tracked configuration file from discovery. Do not treat `.gitignore` as a security boundary.

`.onopenignore` is repository data. Suppressed findings remain counted and remain present in JSON and SARIF, but a repository can ship suppressions alongside a payload. When reviewing an untrusted repository, scan with a reviewer-owned ignore file or inspect every suppressed finding. Suppression is not evidence of review.

Symlinks to files outside the scan root are not followed. They are reported as unreadable because their contents are machine-local and not part of the repository being reviewed. Directory symlinks are not traversed. Platform-specific junctions and filesystem aliases may not be identifiable with identical semantics on every operating system.

Files larger than the configured maximum, unsupported encodings, and malformed documents are incomplete scans, not clean files. Onopen reports them and exits with a scan error. A parser accepting a file does not prove that the target tool interprets every edge case identically.

The default depth is finite. Repositories with executable configuration below that depth require a larger `--depth`. Dependency directories such as `node_modules`, `vendor`, and `target` are never scanned because they are installed/generated inputs rather than versioned project configuration.

# Part 4 — Launch

## a. crates.io metadata

- **Description (91 characters):** `Static CLI that shows which repository configs execute on open, install, test, or build.`
- **Keywords:** `security`, `supply-chain`, `static-analysis`, `devsecops`, `scanner`
- **Categories:** `command-line-utilities`, `development-tools`, `development-tools::testing`

The current longer manifest description should be replaced with the one-line form so crates.io search results state both the mechanism and the boundary.

## b. Honest comparison

| Tool | What it covers that Onopen does not | What Onopen covers that it generally does not |
|---|---|---|
| Socket | Package behavior, known malware, typosquats, obfuscation, maintainer/package signals, dependency changes, and transitive package analysis. Socket's CLI/API uses network services for many analyses. | Repository-local IDE tasks, agent hooks, MCP processes, devcontainer host commands, local environment hooks, and build-tool wrappers before dependency behavior is the question. [Socket supply-chain risks](https://docs.socket.dev/docs/supply-chain-risk), [Socket for GitHub](https://docs.socket.dev/docs/socket-for-github), [Socket CLI network behavior](https://docs.socket.dev/docs/socket-cli-faq) |
| Snyk | Known dependency vulnerabilities and licenses (SCA), first-party code vulnerabilities (SAST), containers, IaC, prioritization, monitoring, and remediation PRs. | A small offline inventory of local config execution triggers independent of vulnerability databases and accounts. [Snyk Open Source](https://docs.snyk.io/scan-with-snyk/snyk-open-source), [Snyk scanning products](https://docs.snyk.io/scan-with-snyk) |
| Dependabot | Advisory-backed vulnerable/malicious dependency alerts and automated security/version update PRs through GitHub's dependency graph. | Nondependency execution paths in editor, agent, MCP, environment, and build configuration; offline pre-open review. [Dependabot alerts](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-alerts) |
| OpenSSF Scorecard | Project security posture: maintenance, review, branch protection, pinned CI dependencies, token permissions, security policy, signed releases, SAST, SBOM, and known vulnerabilities. | Concrete commands a cloned repository asks local developer tools to execute. Scorecard evaluates project practices; Onopen evaluates versioned execution-bearing configuration. [Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md) |
| npq | npm package/version maturity, publisher history, typosquatting, install scripts inside dependencies, signatures, provenance, known vulnerabilities, and package health before installation. | Ecosystems and configuration outside the npm package being selected, including the root repository's editor/agent/MCP/devcontainer/environment execution. [npq checks](https://github.com/lirantal/npq) |
| `npm audit` | Known vulnerabilities in the resolved npm dependency tree, meta-vulnerabilities, remediations, registry signatures, and provenance attestations. | Unknown or non-advisory execution paths in the root repository and all non-npm config. It also stays offline by design while `npm audit` submits dependency data to a registry. [npm audit](https://docs.npmjs.com/cli/v11/commands/npm-audit/) |
| GitHub code scanning | General vulnerability/error analysis from CodeQL and third-party SARIF tools, data-flow presentation, PR annotations, and centralized triage. | Nothing inherently: code scanning is a result platform plus analyzers. Onopen contributes its narrow rule set to it through SARIF and can run locally without GitHub. [GitHub code scanning](https://docs.github.com/en/code-security/reference/code-scanning), [SARIF uploads](https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files) |

Socket overlaps most directly on install scripts and mutable package inputs. It is broader and deeper for package risk. Onopen's distinct value is not “better supply-chain scanning”; it is the narrow, offline question of which versioned repository configurations cause local tools to start processes.

## c. Launch copy

### Hacker News

**Title:** `Show HN: Onopen — an offline scanner for repository configs that execute code`

**First comment:**

> The limitation first: a clean result is not a safety proof. Onopen only understands a documented set of configuration paths, and it reports execution, not malicious intent.
>
> I built it after realizing that “review the code before you run it” no longer covers what happens when a repository is opened. A trusted VS Code workspace can run a `folderOpen` task; an agent session can start command hooks and MCP servers; a devcontainer has a host-side `initializeCommand`; package managers and environment tools load repository scripts before application code.
>
> Onopen is a Rust CLI that reads those versioned configs and prints the trigger and command. It does not execute found commands, evaluate project code, contact a service, send telemetry, or require an account. Output is human-readable, JSON, and SARIF. It can also run as a GitHub Action.
>
> Version 0.3.0 adds Cursor hooks, multi-root VS Code workspace tasks, pnpm/Yarn execution paths, Python and Cargo build hooks, direnv/mise/Nix environment hooks, explicit unreadable-file reporting, encoding/resource limits, and symlink containment.
>
> The design tradeoff is noise. I intentionally do not report every Makefile, Dockerfile, Gradle build, CI workflow, or agent instruction containing the word “run.” Those are real execution surfaces, but a scanner that restates that all build programs execute code becomes background noise.
>
> I would especially value adversarial fixtures: small repositories that execute locally through a versioned config Onopen currently reports as clean.

### X

> I built Onopen: an offline Rust CLI that answers “what repository config will execute on my machine?”
>
> It finds editor tasks, agent hooks, MCP servers, install/build scripts, devcontainer host commands, and environment hooks. No execution, network, account, or telemetry.
>
> A clean result is not a safety proof—and the README says exactly where coverage ends.
>
> https://github.com/NULVEC/onopen

## d. Hard objections and answers

### 1. “This is just grep over config files. Why is it a product?”

The parsing is not the product claim. The useful part is a maintained mapping from each tool's versioned schema to an execution trigger, consistent severity semantics, hostile fixtures, subproject discovery, and outputs that preserve uncertainty. Grep misses JSONC, Unicode escapes, command arrays/objects, workspace task dependencies, renamed build scripts, alternate encodings, and fields that move between product versions. Onopen should remain small enough that a reviewer can audit it; complexity is not a goal.

### 2. “Workspace trust and package-manager prompts already solve this.”

They are necessary boundaries, but they ask for a broad decision: trust this workspace, allow this environment, install this project. They usually do not present a complete list of the commands enabled by that decision. Onopen is the pre-decision inventory. It does not replace trust prompts; it makes them informed. The tool must also state when a content-bound prompt exists—direnv is deferred for exactly that reason.

### 3. “A clean scan will create dangerous false confidence because arbitrary build files and prose can still execute.”

That objection is correct if the tool markets “clean” as “safe.” It must not. The CLI and README should say “no supported execution paths found,” report unreadable files as scan failures, list unsupported families, and retain suppressed findings in machine output. The narrow question is still useful if its boundary is explicit. A scanner that hides parse failures or unsupported surfaces would be worse than no scanner; 0.3.0 treats those as release-blocking design issues.

