//! `.gitignore` must not decide what onopen is allowed to see.
//!
//! Git applies ignore rules to files it does not already track. A file that was
//! committed first stays committed, ships in every clone, and runs on the
//! machine of whoever opens it — the pattern added afterwards changes nothing
//! except which tools notice. That is a two-line evasion:
//!
//! ```text
//! git add -f packages/api/.vscode/tasks.json
//! echo 'packages/' >> .gitignore
//! ```
//!
//! and until the index was read it took onopen from "one immediate finding,
//! exit 1" to "nothing executes on open, exit 0".
//!
//! The repositories here are built byte by byte rather than with `git`. The
//! index format is what is under test, `git` is not installed on every machine
//! that runs this suite, and a fixture that shells out to it would be testing
//! whichever version happened to be on `PATH`.

use onopen::finding::ScanUnit;
use onopen::{ScanOptions, scan};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A task that runs the moment the folder is opened. Dull on purpose: what is
/// under test is whether the file is looked at, not what it would run.
const FOLDER_OPEN_TASK: &str = r#"{"version":"2.0.0","tasks":[{"label":"setup","type":"shell","command":"node ./tools/setup.js","runOptions":{"runOn":"folderOpen"}}]}"#;

fn repo(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onopen-tracked-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn put(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

/// Write a version 2 index listing exactly these paths, the way git writes one.
fn track(root: &Path, paths: &[&str]) {
    let mut sorted: Vec<&str> = paths.to_vec();
    sorted.sort_unstable();

    let mut entries = Vec::new();
    for path in &sorted {
        let start = entries.len();
        entries.extend_from_slice(&[0u8; 40]); // stat data, unused by onopen
        entries.extend_from_slice(&[0x11u8; 20]); // object name
        let name_len = u16::try_from(path.len()).unwrap_or(0xFFF).min(0xFFF);
        entries.extend_from_slice(&name_len.to_be_bytes());
        entries.extend_from_slice(path.as_bytes());
        entries.push(0);
        // One to eight NUL bytes, padding the entry to a multiple of eight.
        let used = entries.len() - start;
        entries.resize(start + used.next_multiple_of(8), 0);
    }

    let mut index = Vec::from(*b"DIRC");
    index.extend_from_slice(&2u32.to_be_bytes());
    index.extend_from_slice(&u32::try_from(sorted.len()).unwrap().to_be_bytes());
    index.extend_from_slice(&entries);
    index.extend_from_slice(&[0u8; 20]); // trailing checksum

    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".git/index"), index).unwrap();
}

fn scan_repo(dir: &Path) -> ScanUnit {
    scan(dir, &ScanOptions::default()).expect("repository should scan")
}

fn rules(unit: &ScanUnit) -> Vec<&str> {
    unit.findings.iter().map(|f| f.rule).collect()
}

#[test]
fn a_committed_task_is_found_even_when_gitignore_covers_it() {
    let dir = repo("committed");
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\n");
    track(&dir, &["packages/api/.vscode/tasks.json", ".gitignore"]);

    let unit = scan_repo(&dir);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "a tracked task hidden behind an ignore rule is still in every clone, \
         got {:?}",
        rules(&unit)
    );
    assert_eq!(
        unit.findings[0].file, "packages/api/.vscode/tasks.json",
        "the path should read from the top of the scan"
    );
}

#[test]
fn ignoring_the_config_directory_itself_does_not_hide_it() {
    // The narrower version of the same trick: ignore `.vscode` rather than the
    // workspace, so only the interesting directory disappears.
    let dir = repo("dotdir");
    put(&dir, ".vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, "apps/web/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, "apps/web/package.json", "{}");
    put(&dir, ".gitignore", ".vscode/\n");
    track(&dir, &[".vscode/tasks.json", "apps/web/.vscode/tasks.json"]);

    let unit = scan_repo(&dir);
    let files: Vec<&str> = unit.findings.iter().map(|f| f.file.as_str()).collect();
    assert!(
        files.contains(&"apps/web/.vscode/tasks.json"),
        "got {files:?}"
    );
}

#[test]
fn an_untracked_ignored_directory_stays_ignored() {
    // The correction only puts back what is committed. Build output and local
    // scratch directories are ignored *and* untracked, and walking into them
    // was never the point.
    let dir = repo("untracked");
    put(&dir, "scratch/app/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "scratch/\n");
    track(&dir, &[".gitignore"]);

    let unit = scan_repo(&dir);
    assert!(
        unit.findings.is_empty(),
        "nothing in scratch/ is in the clone, got {:?}",
        rules(&unit)
    );
}

#[test]
fn a_repository_with_no_index_behaves_as_before() {
    // `git init` and nothing staged: no index, nothing tracked, and ignore
    // rules are then the whole truth about what a clone would contain.
    let dir = repo("no-index");
    put(&dir, "hidden/app/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "hidden/\n");
    fs::create_dir_all(dir.join(".git")).unwrap();

    assert!(scan_repo(&dir).findings.is_empty());
}

#[test]
fn an_index_that_cannot_be_read_is_reported_and_hides_nothing() {
    // The one case where the ignore rules cannot be checked against what is
    // committed. Trusting them anyway would let a damaged index do the same job
    // the evasion did; the walk stops honouring them, and the report says why.
    let dir = repo("damaged");
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\n");
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(
        dir.join(".git/index"),
        b"DIRC\x00\x00\x00\x02\xff\xff\xff\xff",
    )
    .unwrap();

    let unit = scan_repo(&dir);
    let entry = unit
        .unreadable
        .iter()
        .find(|u| u.file == ".git/index")
        .expect("an index that does not parse is not an index that says nothing");
    assert!(
        !entry.reason.is_empty(),
        "the reason has to be something a person can act on"
    );
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "with no index to check them against, ignore rules stop being trusted"
    );
}

#[test]
fn a_worktree_git_file_points_at_the_real_index() {
    // A linked worktree or a submodule puts a file at `.git` holding the path
    // to the directory the index actually lives in.
    let dir = repo("worktree");
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\n");

    let real = dir.join("elsewhere/worktrees/api");
    fs::create_dir_all(&real).unwrap();
    track(&real, &["packages/api/.vscode/tasks.json"]);
    fs::rename(real.join(".git/index"), real.join("index")).unwrap();
    fs::write(dir.join(".git"), "gitdir: ./elsewhere/worktrees/api\n").unwrap();

    assert!(
        rules(&scan_repo(&dir)).contains(&"vscode/task-run-on-folder-open"),
        "the index named by a `.git` file is the one that counts"
    );
}

#[test]
fn the_scan_exits_two_when_the_index_is_unreadable() {
    let dir = repo("exit-code");
    put(&dir, ".git/index", "not an index");

    let output = Command::new(env!("CARGO_BIN_EXE_onopen"))
        .arg(&dir)
        .env("NO_COLOR", "1")
        .output()
        .expect("onopen should run");

    assert_eq!(
        output.status.code(),
        Some(2),
        "a scan that could not read the index has not answered the question"
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(".git/index"), "got:\n{text}");
}
