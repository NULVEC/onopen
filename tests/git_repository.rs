//! Scans against a repository that has a real `.git` directory.
//!
//! These two rules went untested from the first commit for a mechanical reason:
//! git will not store a nested `.git` directory, so the cases cannot be
//! committed as fixtures the way every other rule's can. They are built here
//! instead — which is worth doing, because `git/active-hook` is one of the few
//! rules that reports something already live in the clone rather than something
//! waiting to be triggered.

use onopen::finding::{ScanUnit, Severity};
use onopen::{ScanOptions, scan};
use std::fs;
use std::path::{Path, PathBuf};

fn repo(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onopen-git-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".git/hooks")).unwrap();
    dir
}

fn scan_repo(dir: &Path) -> ScanUnit {
    scan(dir, &ScanOptions::default()).expect("repository should scan")
}

#[test]
fn reports_a_live_hook_in_the_clone() {
    let dir = repo("live-hook");
    fs::write(
        dir.join(".git/hooks/pre-commit"),
        "#!/bin/sh\n# set up\nnode ./tools/report.js\n",
    )
    .unwrap();

    let unit = scan_repo(&dir);
    let hit = unit
        .findings
        .iter()
        .find(|f| f.rule == "git/active-hook")
        .expect("a hook in .git/hooks is live right now");

    assert_eq!(hit.severity, Severity::Immediate);
    assert!(hit.trigger.contains("pre-commit"));
    assert_eq!(
        hit.command, "node ./tools/report.js",
        "the shebang and the comment are not what the hook does"
    );
}

#[test]
fn ignores_the_sample_hooks_git_ships() {
    // Every clone has these and none of them run. A scanner that reports all
    // fourteen on an untouched repository has taught the reader to skip its
    // output before they have read anything real.
    let dir = repo("samples");
    for name in ["pre-commit.sample", "pre-push.sample", "update.sample"] {
        fs::write(
            dir.join(".git/hooks").join(name),
            "#!/bin/sh\necho sample\n",
        )
        .unwrap();
    }

    let unit = scan_repo(&dir);
    assert!(
        !unit.findings.iter().any(|f| f.rule == "git/active-hook"),
        "sample hooks are inert: {:#?}",
        unit.findings
    );
}

#[test]
fn reports_a_hooks_path_pointed_back_into_the_repository() {
    // This is the line that turns a directory of committed scripts into live
    // hooks, so it is the one that makes `git/checked-in-hook` immediate rather
    // than deferred.
    let dir = repo("hookspath");
    fs::write(
        dir.join(".git/config"),
        "[core]\n\trepositoryformatversion = 0\n\thooksPath = .githooks\n",
    )
    .unwrap();

    let unit = scan_repo(&dir);
    let hit = unit
        .findings
        .iter()
        .find(|f| f.rule == "git/hooks-path-redirected")
        .expect("a redirected hooksPath should be reported");

    assert_eq!(hit.severity, Severity::Immediate);
    assert_eq!(hit.command, ".githooks");
}

#[test]
fn an_ordinary_git_config_is_not_a_finding() {
    let dir = repo("plain-config");
    fs::write(
        dir.join(".git/config"),
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
    )
    .unwrap();

    let unit = scan_repo(&dir);
    assert!(
        unit.findings.is_empty(),
        "a normal .git/config says nothing: {:#?}",
        unit.findings
    );
}
