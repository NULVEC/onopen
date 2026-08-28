//! The contract an `.onopenignore` has to keep.
//!
//! Suppression is the feature that decides whether a scanner survives contact
//! with a real repository: without it the first false positive is also the last
//! run. It is also the feature that can quietly turn the tool off, so the rules
//! below are the ones that keep it honest — silencing is allowed, silence about
//! silencing is not.

use onopen::finding::ScanUnit;
use onopen::suppress::Suppressions;
use onopen::{ScanOptions, scan};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo(name: &str, ignore: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onopen-ignore-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".vscode")).unwrap();
    fs::write(
        dir.join(".vscode/tasks.json"),
        r#"{"tasks":[{"label":"boot","command":"node ./tools/boot.js","runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();
    fs::write(dir.join(".onopenignore"), ignore).unwrap();
    dir
}

fn scan_repo(dir: &Path) -> ScanUnit {
    scan(dir, &ScanOptions::default()).expect("repository should scan")
}

#[test]
fn silencing_everything_is_refused() {
    // `*  *` is not configuration, it is turning the scanner off, and there is
    // already a way to not run it. Accepting the line would leave a repository
    // reporting clean with the tool's full authority behind it.
    let err = Suppressions::parse("*  *\n").expect_err("`* *` must not be accepted");
    let message = format!("{err:#}");
    assert!(
        message.contains("every finding"),
        "the error should say what the line would do: {message}"
    );
}

#[test]
fn silencing_every_rule_in_one_directory_is_allowed() {
    // The refusal above is about scope, not about the wildcard. Vendored code
    // is a legitimate thing to stop reading.
    let rules = Suppressions::parse("*  vendor/**  # not our code\n")
        .expect("a wildcard rule bounded by a path is ordinary");
    assert!(!rules.is_empty());
}

#[test]
fn a_line_that_silences_nothing_is_reported() {
    // The quiet failure of an ignore file: the rule id was renamed or the path
    // moved, and the line now protects nothing. Whoever reads the file still
    // believes it does, which is worse than having no line at all.
    let dir = repo(
        "stale",
        "vscode/task-run-on-folder-open  .vscode/tasks.json\nnpm/install-lifecycle-script  package.json\n",
    );

    let unit = scan_repo(&dir);
    assert_eq!(unit.suppressed.len(), 1, "line 1 still matches");
    assert_eq!(
        unit.stale_ignore_lines,
        vec![2],
        "line 2 names a file this repository does not have"
    );
}

#[test]
fn every_line_pulling_its_weight_reports_nothing_stale() {
    let dir = repo(
        "live",
        "vscode/task-run-on-folder-open  .vscode/tasks.json\n",
    );
    let unit = scan_repo(&dir);
    assert!(unit.stale_ignore_lines.is_empty());
}

#[test]
fn an_otherwise_clean_report_still_says_what_was_silenced() {
    // The whole argument for keeping suppressed findings rather than dropping
    // them. A reader who sees "nothing executes on open" has to see, in the
    // same breath, that something was hidden to get there.
    let dir = repo("clean-looking", "*  .vscode/**  # reviewed\n");

    let output = Command::new(env!("CARGO_BIN_EXE_onopen"))
        .arg(&dir)
        .arg("--quiet")
        .env("NO_COLOR", "1")
        .output()
        .expect("onopen should run");

    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("nothing executes on open"),
        "expected a clean-looking report, got:\n{text}"
    );
    assert!(
        text.contains("1 finding silenced by an ignore file"),
        "a clean report must still count what was hidden:\n{text}"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "silenced findings do not fail"
    );
}

#[test]
fn show_suppressed_prints_what_was_hidden() {
    let dir = repo("readable", "*  .vscode/**  # reviewed\n");

    let output = Command::new(env!("CARGO_BIN_EXE_onopen"))
        .arg(&dir)
        .arg("--show-suppressed")
        .env("NO_COLOR", "1")
        .output()
        .expect("onopen should run");

    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("tools/boot.js"),
        "the hidden finding must be readable on request:\n{text}"
    );
}
