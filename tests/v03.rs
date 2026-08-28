use onopen::{ScanOptions, scan};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn repo(label: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("onopen-v03-{label}-{}-{n}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn put(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn rules(root: &Path) -> BTreeSet<&'static str> {
    scan(root, &ScanOptions::default())
        .unwrap()
        .findings
        .into_iter()
        .map(|f| f.rule)
        .collect()
}

#[test]
fn every_v03_execution_surface_has_a_hostile_fixture() {
    let root = repo("trapped");
    put(
        &root,
        ".cursor/hooks.json",
        r#"{"hooks":{"sessionStart":[{"command":"./scripts/bootstrap.sh"}]}}"#,
    );
    put(
        &root,
        "project.code-workspace",
        r#"{"tasks":{"tasks":[{"label":"bootstrap","command":"node","args":["open.js"],"runOptions":{"runOn":"folderOpen"},"dependsOn":"prepare"},{"label":"prepare","command":"node prepare.js","windows":{"command":"pwsh prepare.ps1"}}]}}"#,
    );
    put(
        &root,
        ".pnpmfile.cjs",
        "module.exports = { hooks: { readPackage(pkg) { return pkg } } };\n",
    );
    put(
        &root,
        ".yarnrc.yml",
        "yarnPath: ./tools/yarn-bootstrap.js\nplugins:\n  - path: ./.yarn/plugins/audit.cjs\n    spec: audit-tools\n",
    );
    put(
        &root,
        "pnpm-workspace.yaml",
        "dangerouslyAllowAllBuilds: true\n",
    );
    put(
        &root,
        "setup.py",
        "from setuptools import setup\nsetup(name='demo')\n",
    );
    put(
        &root,
        "pyproject.toml",
        "[build-system]\nrequires=[]\nbuild-backend='local_backend.api'\nbackend-path=['.']\n",
    );
    put(&root, "tests/conftest.py", "import subprocess\n");
    put(&root, "sitecustomize.py", "import bootstrap\n");
    put(
        &root,
        "Cargo.toml",
        "[package]\nname='demo'\nversion='0.1.0'\nbuild='tools/bootstrap.rs'\n",
    );
    put(
        &root,
        ".cargo/config.toml",
        "[build]\nrustc-wrapper='./tools/rustc-wrapper'\n",
    );
    put(
        &root,
        ".envrc",
        "source_url https://example.test/env.sh sha256-deadbeef\n",
    );
    put(
        &root,
        "mise.toml",
        // `enter` runs on entering the directory; a watch-file hook waits for a
        // matching file to change, which is a deliberate act, so deferred.
        "[hooks]\nenter={ run='./tools/bootstrap.sh' }\n\n[[watch_files]]\npatterns=['src/**']\nrun='./tools/regen.sh'\n",
    );
    put(
        &root,
        "shell.nix",
        "{ pkgs ? import <nixpkgs> {} }: pkgs.mkShell { shellHook = ''\n ./tools/bootstrap.sh\n''; }\n",
    );
    put(
        &root,
        ".pre-commit-config.yaml",
        "repos:\n  - repo: local\n    hooks:\n      - id: bootstrap\n        language: system\n        entry: ./tools/bootstrap.sh\n",
    );

    let got = rules(&root);
    for expected in [
        "agent/cursor-command-hook",
        "vscode/workspace-task-run-on-folder-open",
        "pnpm/pnpmfile-hook",
        "yarn/yarn-path",
        "yarn/local-plugin",
        "pnpm/dependency-build-approval",
        "python/setup-script",
        "python/local-build-backend",
        "python/pytest-conftest",
        "python/sitecustomize",
        "cargo/build-script",
        "cargo/compiler-wrapper",
        "direnv/environment-script",
        "mise/automatic-hook",
        "mise/watch-file-hook",
        "nix/shell-hook",
        "git/pre-commit-local-entry",
    ] {
        assert!(
            got.contains(expected),
            "{expected} did not fire; got {got:#?}"
        );
    }
}

#[test]
fn ordinary_counterparts_stay_clean() {
    let root = repo("clean");
    put(&root, ".cursor/hooks.json", r#"{"hooks":{}}"#);
    put(
        &root,
        "project.code-workspace",
        r#"{"tasks":{"tasks":[{"label":"build","command":"cargo build","runOptions":{"runOn":"default"}}]}}"#,
    );
    put(&root, ".pnpmfile.cjs", "// placeholder\n");
    put(
        &root,
        ".yarnrc.yml",
        "nodeLinker: node-modules\nplugins: []\n",
    );
    put(
        &root,
        "pnpm-workspace.yaml",
        "dangerouslyAllowAllBuilds: false\nallowBuilds: {}\n",
    );
    put(
        &root,
        "pyproject.toml",
        "[build-system]\nrequires=['setuptools>=77']\nbuild-backend='setuptools.build_meta'\n",
    );
    put(
        &root,
        "Cargo.toml",
        "[package]\nname='demo'\nversion='0.1.0'\nbuild=false\n",
    );
    put(
        &root,
        ".cargo/config.toml",
        "[build]\ntarget-dir='target'\n",
    );
    put(&root, ".envrc", "# no environment script\n");
    put(&root, "mise.toml", "[tools]\nnode='24'\n");
    put(
        &root,
        "shell.nix",
        "{ pkgs ? import <nixpkgs> {} }: pkgs.mkShell {}\n",
    );
    put(&root, ".pre-commit-config.yaml", "repos: []\n");

    let unit = scan(&root, &ScanOptions::default()).unwrap();
    assert!(
        unit.findings.is_empty(),
        "clean fixture findings: {:#?}",
        unit.findings
    );
    assert!(
        unit.unreadable.is_empty(),
        "clean fixture unreadable: {:#?}",
        unit.unreadable
    );
}

#[test]
fn malformed_toml_and_yaml_are_incomplete_not_clean() {
    let root = repo("bad-structured-config");
    put(&root, "pyproject.toml", "[build-system\nbuild-backend='x'");
    put(&root, ".yarnrc.yml", "plugins: [unterminated");

    let unit = scan(&root, &ScanOptions::default()).unwrap();
    assert!(unit.findings.is_empty());
    assert_eq!(unit.unreadable.len(), 2, "{:#?}", unit.unreadable);
    assert!(unit.unreadable.iter().any(|u| u.reason.contains("TOML")));
    assert!(unit.unreadable.iter().any(|u| u.reason.contains("YAML")));
}

fn exit(root: &Path, extra: &[&str]) -> i32 {
    let mut command = Command::new(env!("CARGO_BIN_EXE_onopen"));
    command.arg(root).arg("--quiet").args(extra);
    command.status().unwrap().code().unwrap()
}

#[test]
fn cli_exit_codes_distinguish_findings_from_incomplete_scans() {
    let clean = repo("exit-clean");
    put(&clean, "package.json", "{}");
    assert_eq!(exit(&clean, &[]), 0);

    let trapped = repo("exit-trapped");
    put(
        &trapped,
        "package.json",
        r#"{"scripts":{"preinstall":"node stage.js"}}"#,
    );
    assert_eq!(exit(&trapped, &[]), 1);
    assert_eq!(exit(&trapped, &["--no-fail"]), 0);

    let incomplete = repo("exit-incomplete");
    put(&incomplete, ".vscode/tasks.json", "{ broken");
    assert_eq!(exit(&incomplete, &[]), 2);
    assert_eq!(exit(&incomplete, &["--no-fail"]), 2);

    assert_eq!(exit(&clean, &["--only", "nope"]), 2);
}
