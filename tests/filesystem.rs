//! Scans against repositories whose trick is the file system itself.
//!
//! `hostile.rs` covers files that are hard to read. These are files that are
//! not what their name says: a directory that is really a link out of the
//! repository, an `.onopenignore` that is a FIFO or `/dev/zero`, a hook script
//! that is a link, a path longer than Windows used to allow, a name that is not
//! UTF-8. The rules the code is held to:
//!
//! - nothing outside the scanned root is read because the repository said so;
//! - nothing that is not a regular file is read, so nothing can hang the scan;
//! - a linked file inside the repository is read like any other, because the
//!   tool that runs it will follow the link too.
//!
//! Links that the platform refuses to create (Windows without developer mode)
//! make the test stand down instead of failing. Junctions need no privilege on
//! Windows, so the directory-link cases always run there.

use onopen::finding::ScanUnit;
use onopen::scanners::MAX_CONFIG_BYTES;
use onopen::{ScanOptions, scan};
use std::fs;
use std::path::{Path, PathBuf};

const FOLDER_OPEN_TASK: &str = r#"{"version":"2.0.0","tasks":[{"label":"setup","type":"shell","command":"node ./tools/setup.js","runOptions":{"runOn":"folderOpen"}}]}"#;

fn fresh(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onopen-fs-{name}"));
    let _ = remove(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `remove_dir_all` on a tree holding a junction removes the junction, never
/// what it points at; on Unix it does not follow symlinks either.
fn remove(dir: &Path) -> std::io::Result<()> {
    fs::remove_dir_all(dir)
}

fn scan_repo(dir: &Path) -> ScanUnit {
    scan(dir, &ScanOptions::default()).expect("the repository still scans")
}

fn scan_err(dir: &Path, options: &ScanOptions) -> String {
    match scan(dir, options) {
        Ok(unit) => panic!("expected the scan to refuse, got {unit:?}"),
        Err(e) => format!("{e:#}"),
    }
}

fn rules(unit: &ScanUnit) -> Vec<&str> {
    unit.findings.iter().map(|f| f.rule).collect()
}

fn symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link)
    }
}

/// A link to a directory: a symlink on Unix, a junction on Windows. A junction
/// is the one an attacker would reach for there — any user can create one, and
/// `symlink_metadata` on a file beneath it reports an ordinary file.
fn link_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other("mklink /J failed"))
        }
    }
}

fn assert_only_unreadable(unit: &ScanUnit, file: &str, contains: &str) {
    assert_eq!(
        unit.unreadable.len(),
        1,
        "expected exactly one unreadable file, got {:?}",
        unit.unreadable
    );
    let entry = &unit.unreadable[0];
    assert_eq!(entry.file, file);
    assert!(
        entry.reason.contains(contains),
        "reason was {:?}, expected it to mention {contains:?}",
        entry.reason
    );
    assert!(
        unit.findings.is_empty(),
        "nothing outside the repository may be read, got {:?}",
        unit.findings
    );
}

#[test]
fn a_config_directory_linked_out_of_the_repository_is_not_read() {
    // `.vscode/tasks.json` itself is a plain file here; the link is one level
    // up. Checking only whether the last component is a link read it anyway.
    let outside = fresh("outside-vscode");
    fs::write(outside.join("tasks.json"), FOLDER_OPEN_TASK).unwrap();
    let dir = fresh("linked-vscode");

    if link_dir(&outside, &dir.join(".vscode")).is_err() {
        eprintln!("skipped: this platform will not create directory links here");
        return;
    }

    let unit = scan_repo(&dir);
    assert_only_unreadable(&unit, ".vscode/tasks.json", "leaving the repository");
}

#[test]
fn a_devcontainer_directory_linked_out_of_the_repository_is_not_read() {
    // The dev container scanner walks `.devcontainer/`, and a walker told not
    // to follow links still enters the directory it was started on.
    let outside = fresh("outside-devcontainer");
    fs::create_dir_all(outside.join("app")).unwrap();
    fs::write(
        outside.join("app/devcontainer.json"),
        r#"{"initializeCommand":"node ./setup.js"}"#,
    )
    .unwrap();
    let dir = fresh("linked-devcontainer");

    if link_dir(&outside, &dir.join(".devcontainer")).is_err() {
        eprintln!("skipped: this platform will not create directory links here");
        return;
    }

    let unit = scan_repo(&dir);
    assert_only_unreadable(
        &unit,
        ".devcontainer/app/devcontainer.json",
        "leaving the repository",
    );
}

#[test]
fn a_config_directory_linked_within_the_repository_is_read() {
    // The same layout pointing inside the repository is how monorepos share
    // editor settings. Refusing it would be a false negative dressed as care.
    let dir = fresh("linked-vscode-inside");
    fs::create_dir_all(dir.join("shared/vscode")).unwrap();
    fs::write(dir.join("shared/vscode/tasks.json"), FOLDER_OPEN_TASK).unwrap();

    if link_dir(&dir.join("shared").join("vscode"), &dir.join(".vscode")).is_err() {
        eprintln!("skipped: this platform will not create directory links here");
        return;
    }

    let unit = scan_repo(&dir);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "got {unit:?}"
    );
    assert!(unit.unreadable.is_empty(), "got {:?}", unit.unreadable);
}

#[test]
fn a_linked_hook_script_is_reported_like_a_copied_one() {
    // Git runs `.githooks/pre-commit` whether it is a file or a link to one.
    // A walker that does not follow links sees the link as neither, and the
    // hook used to vanish from the report.
    let dir = fresh("linked-hook");
    fs::create_dir_all(dir.join("scripts")).unwrap();
    fs::create_dir_all(dir.join(".githooks")).unwrap();
    fs::write(dir.join("scripts/pre-commit.sh"), "#!/bin/sh\nmake lint\n").unwrap();

    if symlink_file(
        &dir.join("scripts/pre-commit.sh"),
        &dir.join(".githooks/pre-commit"),
    )
    .is_err()
    {
        eprintln!("skipped: this platform will not create symbolic links here");
        return;
    }

    let unit = scan_repo(&dir);
    let hook = unit
        .findings
        .iter()
        .find(|f| f.rule == "git/checked-in-hook")
        .unwrap_or_else(|| panic!("the linked hook must be reported, got {unit:?}"));
    assert_eq!(hook.file, ".githooks/pre-commit");
    assert!(hook.command.contains("make lint"), "got {:?}", hook.command);
}

#[test]
fn a_linked_conftest_is_reported() {
    let dir = fresh("linked-conftest");
    fs::create_dir_all(dir.join("shared")).unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();
    fs::write(dir.join("shared/conftest.py"), "import os\nos.getcwd()\n").unwrap();

    if symlink_file(
        &dir.join("shared/conftest.py"),
        &dir.join("tests/conftest.py"),
    )
    .is_err()
    {
        eprintln!("skipped: this platform will not create symbolic links here");
        return;
    }

    let unit = scan_repo(&dir);
    let files: Vec<&str> = unit
        .findings
        .iter()
        .filter(|f| f.rule == "python/pytest-conftest")
        .map(|f| f.file.as_str())
        .collect();
    assert!(files.contains(&"tests/conftest.py"), "got {unit:?}");
}

// --- `.onopenignore` -------------------------------------------------------

#[test]
fn an_ignore_file_linked_out_of_the_repository_is_refused() {
    // Parsed, it would have had its first bad line quoted back in the error:
    // a repository choosing which file on this machine gets printed.
    let outside = fresh("outside-ignore").join("secrets.txt");
    fs::write(&outside, "api_key = 1234\n").unwrap();
    let dir = fresh("linked-ignore");

    if symlink_file(&outside, &dir.join(".onopenignore")).is_err() {
        eprintln!("skipped: this platform will not create symbolic links here");
        return;
    }

    let message = scan_err(&dir, &ScanOptions::default());
    assert!(message.contains("leaving the repository"), "{message}");
    assert!(!message.contains("1234"), "{message}");
}

#[test]
fn an_ignore_file_that_is_a_directory_is_refused() {
    let dir = fresh("ignore-directory");
    fs::create_dir_all(dir.join(".onopenignore")).unwrap();

    let message = scan_err(&dir, &ScanOptions::default());
    assert!(message.contains("not a regular file"), "{message}");
}

#[test]
fn an_ignore_file_too_large_to_be_one_is_refused() {
    let dir = fresh("ignore-huge");
    let file = fs::File::create(dir.join(".onopenignore")).unwrap();
    file.set_len(MAX_CONFIG_BYTES + 1).unwrap();

    let message = scan_err(&dir, &ScanOptions::default());
    assert!(message.contains("MiB"), "{message}");
}

#[test]
fn an_explicit_ignore_file_may_live_outside_the_repository() {
    // A path the user typed is theirs to choose; only the one the repository
    // supplies is held to the root.
    let dir = fresh("ignore-explicit");
    fs::create_dir_all(dir.join(".vscode")).unwrap();
    fs::write(dir.join(".vscode/tasks.json"), FOLDER_OPEN_TASK).unwrap();
    let elsewhere = fresh("ignore-explicit-elsewhere").join("team.onopenignore");
    fs::write(
        &elsewhere,
        "vscode/task-run-on-folder-open  .vscode/tasks.json  # reviewed\n",
    )
    .unwrap();

    let options = ScanOptions {
        ignore_file: Some(elsewhere),
        ..ScanOptions::default()
    };
    let unit = scan(&dir, &options).expect("an explicit ignore file is allowed");
    assert!(unit.findings.is_empty(), "got {:?}", unit.findings);
    assert_eq!(unit.suppressed.len(), 1);
}

#[cfg(windows)]
#[test]
fn an_explicit_ignore_file_naming_a_device_is_refused() {
    let dir = fresh("ignore-device");
    let options = ScanOptions {
        ignore_file: Some(PathBuf::from("NUL")),
        ..ScanOptions::default()
    };
    // `NUL` is not a file; whether Windows says so through metadata or by
    // refusing to resolve it, the scan must not read it as one.
    let message = scan_err(&dir, &options);
    assert!(message.contains("NUL"), "{message}");
}

#[cfg(unix)]
#[test]
fn an_explicit_ignore_file_naming_a_device_is_refused() {
    // `/dev/zero` never ends. Read with `read_to_string`, the scan never did.
    let dir = fresh("ignore-device");
    let options = ScanOptions {
        ignore_file: Some(PathBuf::from("/dev/zero")),
        ..ScanOptions::default()
    };
    let message = scan_err(&dir, &options);
    assert!(message.contains("not a regular file"), "{message}");
}

#[cfg(unix)]
#[test]
fn an_ignore_file_that_is_a_fifo_does_not_hang_the_scan() {
    let dir = fresh("ignore-fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(dir.join(".onopenignore"))
        .status();
    if !status.is_ok_and(|s| s.success()) {
        eprintln!("skipped: mkfifo is not available");
        return;
    }
    let message = scan_err(&dir, &ScanOptions::default());
    assert!(message.contains("not a regular file"), "{message}");
}

#[cfg(unix)]
#[test]
fn a_config_that_is_a_fifo_does_not_hang_the_scan() {
    let dir = fresh("config-fifo");
    fs::create_dir_all(dir.join(".vscode")).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(dir.join(".vscode/tasks.json"))
        .status();
    if !status.is_ok_and(|s| s.success()) {
        eprintln!("skipped: mkfifo is not available");
        return;
    }
    let unit = scan_repo(&dir);
    assert_only_unreadable(&unit, ".vscode/tasks.json", "not a regular file");
}

// --- Names and lengths -----------------------------------------------------

#[test]
fn a_config_past_the_old_windows_path_limit_is_read() {
    // MAX_PATH is 260. A repository nested past it is ordinary in monorepos
    // with deep `node_modules`-style layouts, and a scanner that silently
    // failed to open files there would report them clean.
    let dir = fresh("long-path");
    let mut deep = dir.clone();
    while deep.as_os_str().len() < 300 {
        deep.push("a-directory-name-thirty-chars");
    }
    if fs::create_dir_all(deep.join(".vscode")).is_err() {
        eprintln!("skipped: this file system will not hold a path this long");
        return;
    }
    fs::write(deep.join(".vscode/tasks.json"), FOLDER_OPEN_TASK).unwrap();

    let unit = scan_repo(&deep);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "got {unit:?}"
    );
    assert!(unit.unreadable.is_empty(), "got {:?}", unit.unreadable);
}

#[cfg(unix)]
#[test]
fn a_directory_name_that_is_not_utf8_is_still_scanned() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = fresh("non-utf8");
    let odd = dir.join(OsStr::from_bytes(b"tests-\xff"));
    if fs::create_dir_all(&odd).is_err() {
        eprintln!("skipped: this file system requires UTF-8 names");
        return;
    }
    fs::write(odd.join("conftest.py"), "import os\nos.getcwd()\n").unwrap();

    let unit = scan_repo(&dir);
    let conftest = unit
        .findings
        .iter()
        .find(|f| f.rule == "python/pytest-conftest")
        .unwrap_or_else(|| panic!("the conftest must be reported, got {unit:?}"));
    assert!(
        conftest.file.contains('\u{FFFD}'),
        "got {:?}",
        conftest.file
    );
}
