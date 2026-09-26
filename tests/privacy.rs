//! The README promises that a scan only reads: no cache, lock or log file in the
//! scanned repository or in the directory onopen was started from. These tests
//! hold the binary to that by snapshotting both trees around real runs.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// Every entry under `root`, with what would change if something wrote to it.
/// Directories are included so that a newly created (even empty) directory
/// shows up, and their mtime catches a file created and then removed.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (bool, u64, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = fs::symlink_metadata(entry.path()).unwrap();
            let rel = entry.path().strip_prefix(root).unwrap().to_path_buf();
            out.insert(rel, (meta.is_dir(), meta.len(), meta.modified().unwrap()));
            if meta.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    let meta = fs::metadata(root).unwrap();
    out.insert(PathBuf::new(), (true, 0, meta.modified().unwrap()));
    out
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn workspace(name: &str) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("onopen-privacy-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let repo = base.join("repo");
    let cwd = base.join("cwd");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trapped");
    copy_tree(&fixture, &repo);
    fs::create_dir_all(&cwd).unwrap();
    (repo, cwd)
}

#[test]
fn scanning_writes_nothing_to_the_repository_or_the_working_directory() {
    let (repo, cwd) = workspace("modes");
    let repo_before = snapshot(&repo);
    let cwd_before = snapshot(&cwd);

    for args in [&[][..], &["--json"][..], &["--sarif"][..], &["--quiet"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_onopen"))
            .args(args)
            .arg(&repo)
            .current_dir(&cwd)
            .output()
            .unwrap();
        // The fixture is full of traps: exit 1 means it was actually scanned.
        assert_eq!(output.status.code(), Some(1), "args {args:?}");
    }

    assert_eq!(snapshot(&repo), repo_before, "the scanned tree changed");
    assert_eq!(snapshot(&cwd), cwd_before, "the working directory changed");
    let _ = fs::remove_dir_all(repo.parent().unwrap());
}

#[test]
fn scanning_from_inside_the_repository_writes_nothing() {
    let (repo, _cwd) = workspace("inside");
    let before = snapshot(&repo);

    let output = Command::new(env!("CARGO_BIN_EXE_onopen"))
        .current_dir(&repo)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));

    assert_eq!(snapshot(&repo), before, "the scanned tree changed");
    let _ = fs::remove_dir_all(repo.parent().unwrap());
}
