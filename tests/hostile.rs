//! Scans against repositories built to be hard to read.
//!
//! Every case here is a way to make onopen say nothing about a file that a real
//! editor or agent would read without complaint. Three bytes of byte order mark
//! used to be enough: the file parsed nowhere, the scanner skipped it in
//! silence, and a `runOn: folderOpen` task fetching a shell script came back as
//! "nothing executes on open" with exit 0.
//!
//! The rule these tests hold the code to is that a file which could not be read
//! is never reported as clean, and never reported as nothing at all.
//!
//! The fixtures are built at run time rather than committed. Some of them are
//! not text, one is eight megabytes, and one is a symbolic link that does not
//! survive a checkout on every platform.

use onopen::finding::ScanUnit;
use onopen::scanners::MAX_CONFIG_BYTES;
use onopen::{ScanOptions, scan};
use std::fs;
use std::path::{Path, PathBuf};

/// A `.vscode/tasks.json` that runs a command the moment the folder is opened.
/// Every test uses the same payload, so what varies is only how it is stored.
///
/// The command is deliberately dull. These fixtures are written to a temporary
/// directory at run time, and an antivirus that sees a fresh file holding
/// `curl ... | sh` will quarantine it mid-test — which fails the run for a
/// reason that has nothing to do with the scanner. What is under test here is
/// the trigger, and `runOn: folderOpen` is a finding whatever it runs.
const FOLDER_OPEN_TASK: &str = r#"{"version":"2.0.0","tasks":[{"label":"setup","type":"shell","command":"node ./tools/setup.js","runOptions":{"runOn":"folderOpen"}}]}"#;

fn repo(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onopen-hostile-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".vscode")).unwrap();
    dir
}

fn write_tasks(dir: &Path, bytes: &[u8]) {
    fs::write(dir.join(".vscode/tasks.json"), bytes).unwrap();
}

fn scan_repo(dir: &Path) -> ScanUnit {
    scan(dir, &ScanOptions::default()).expect("a hostile repository still scans")
}

fn rules(unit: &ScanUnit) -> Vec<&str> {
    unit.findings.iter().map(|f| f.rule).collect()
}

/// The one assertion every unreadable case shares: reported, and never filed
/// under the files that came back clean.
fn assert_unreadable(unit: &ScanUnit, contains: &str) {
    assert_eq!(
        unit.unreadable.len(),
        1,
        "expected exactly one unreadable file, got {:?}",
        unit.unreadable
    );
    let entry = &unit.unreadable[0];
    assert_eq!(entry.file, ".vscode/tasks.json");
    assert!(
        entry.reason.contains(contains),
        "reason was {:?}, expected it to mention {contains:?}",
        entry.reason
    );
    assert!(
        !unit.cleared.iter().any(|c| c == ".vscode/tasks.json"),
        "a file that could not be read must never be listed as clean"
    );
    assert!(
        unit.findings.is_empty(),
        "nothing should be claimed about a file that was not read"
    );
}

#[test]
fn reads_a_config_that_starts_with_a_utf8_byte_order_mark() {
    // Editors on Windows write these routinely and VS Code reads them without
    // complaint. Being stricter than the tool that will actually run the file
    // is how a scanner reports clean on a repository that is not.
    let dir = repo("bom");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(FOLDER_OPEN_TASK.as_bytes());
    write_tasks(&dir, &bytes);

    let unit = scan_repo(&dir);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "a byte order mark must not hide a folderOpen task"
    );
    assert!(unit.unreadable.is_empty());
}

#[test]
fn reads_a_config_stored_as_utf16() {
    // PowerShell's `>` still writes UTF-16, so this is an accident as often as
    // it is a trick.
    for (name, big_endian) in [("utf16le", false), ("utf16be", true)] {
        let dir = repo(name);
        let mut bytes = if big_endian {
            vec![0xFE, 0xFF]
        } else {
            vec![0xFF, 0xFE]
        };
        for unit16 in FOLDER_OPEN_TASK.encode_utf16() {
            let pair = if big_endian {
                unit16.to_be_bytes()
            } else {
                unit16.to_le_bytes()
            };
            bytes.extend_from_slice(&pair);
        }
        write_tasks(&dir, &bytes);

        let unit = scan_repo(&dir);
        assert!(
            rules(&unit).contains(&"vscode/task-run-on-folder-open"),
            "{name}: a folderOpen task must be found whatever the encoding"
        );
    }
}

#[test]
fn a_file_that_does_not_parse_is_reported_rather_than_skipped() {
    let dir = repo("unparseable");
    write_tasks(&dir, b"{'tasks': [ this is not json ]}");

    let unit = scan_repo(&dir);
    assert_unreadable(&unit, "not parseable as JSON");
}

#[test]
fn a_config_that_is_not_text_is_reported() {
    let dir = repo("binary");
    write_tasks(&dir, &[0x00, 0x80, 0xC0, 0xFF, 0xFE, 0x00, 0x99]);

    let unit = scan_repo(&dir);
    assert_unreadable(&unit, "not text");
}

#[test]
fn deeply_nested_json_is_reported_instead_of_exhausting_the_stack() {
    // A scanner that can be crashed by the file it was pointed at fails exactly
    // when it matters. This must come back as a report, not as a signal.
    let dir = repo("deep");
    let depth = 100_000;
    let mut bytes = vec![b'['; depth];
    bytes.push(b'1');
    bytes.extend(std::iter::repeat_n(b']', depth));
    write_tasks(&dir, &bytes);

    let unit = scan_repo(&dir);
    assert_unreadable(&unit, "not parseable as JSON");
}

#[test]
fn a_config_too_large_to_be_configuration_is_reported_and_not_read() {
    let dir = repo("huge");
    write_tasks(&dir, &vec![b' '; (MAX_CONFIG_BYTES + 1) as usize]);

    let unit = scan_repo(&dir);
    assert_unreadable(&unit, "onopen will read as configuration");
}

#[test]
fn one_unreadable_file_does_not_stop_the_rest_of_the_scan() {
    let dir = repo("partial");
    write_tasks(&dir, b"{ not json");
    fs::write(
        dir.join("package.json"),
        r#"{"scripts":{"preinstall":"node ./tools/setup.js"}}"#,
    )
    .unwrap();

    let unit = scan_repo(&dir);
    assert_eq!(unit.unreadable.len(), 1);
    assert!(
        rules(&unit).contains(&"npm/install-lifecycle-script"),
        "the readable half of the repository still gets scanned"
    );
}

// Symbolic links need a privilege Windows does not hand out by default. These
// tests create one and stand down if the platform refuses, rather than failing
// on a developer's machine for a reason that has nothing to do with the code.
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

#[test]
fn a_link_out_of_the_repository_is_reported_and_not_followed() {
    let dir = repo("escaping-link");
    let outside = std::env::temp_dir().join("onopen-hostile-outside.json");
    fs::write(&outside, FOLDER_OPEN_TASK).unwrap();

    if symlink_file(&outside, &dir.join(".vscode/tasks.json")).is_err() {
        eprintln!("skipped: this platform will not create symbolic links here");
        return;
    }

    let unit = scan_repo(&dir);
    assert_unreadable(&unit, "leaving the repository");
}

#[test]
fn a_link_within_the_repository_is_read_normally() {
    // Monorepos share one config between workspaces this way. Refusing to
    // follow those would be a false positive on an ordinary layout.
    let dir = repo("internal-link");
    let real = dir.join("shared-tasks.json");
    fs::write(&real, FOLDER_OPEN_TASK).unwrap();

    if symlink_file(&real, &dir.join(".vscode/tasks.json")).is_err() {
        eprintln!("skipped: this platform will not create symbolic links here");
        return;
    }

    let unit = scan_repo(&dir);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "a link inside the repository is ordinary and must be followed"
    );
    assert!(unit.unreadable.is_empty());
}
