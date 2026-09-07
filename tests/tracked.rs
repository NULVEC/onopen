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
use std::fmt::Write as _;
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
    let index = index_bytes(paths);
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".git/index"), index).unwrap();
}

fn index_bytes(paths: &[&str]) -> Vec<u8> {
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

    index
}

fn hex_name(bytes: &[u8]) -> String {
    let mut name = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut name, "{byte:02x}");
    }
    name
}

fn ewah(bit_size: usize, set_bits: &[usize]) -> Vec<u8> {
    let mut literal = 0u64;
    for bit in set_bits {
        literal |= 1u64 << bit;
    }
    let mut bitmap = Vec::new();
    bitmap.extend_from_slice(&u32::try_from(bit_size).unwrap().to_be_bytes());
    if bit_size == 0 {
        bitmap.extend_from_slice(&1u32.to_be_bytes());
        bitmap.extend_from_slice(&0u64.to_be_bytes());
        bitmap.extend_from_slice(&0u32.to_be_bytes());
    } else {
        bitmap.extend_from_slice(&2u32.to_be_bytes());
        bitmap.extend_from_slice(&(1u64 << 33).to_be_bytes());
        bitmap.extend_from_slice(&literal.to_be_bytes());
        bitmap.extend_from_slice(&0u32.to_be_bytes());
    }
    bitmap
}

fn split_index(
    shared: &[&str],
    overlay: &[&str],
    deleted: &[usize],
    replaced: &[usize],
) -> (Vec<u8>, Vec<u8>, String) {
    let shared_index = index_bytes(shared);
    let hash = [0x42u8; 20];
    let shared_name = hex_name(&hash);

    let mut main = index_bytes(overlay);
    main.truncate(main.len() - 20);
    let mut payload = hash.to_vec();
    payload.extend_from_slice(&ewah(shared.len(), deleted));
    payload.extend_from_slice(&ewah(shared.len(), replaced));
    main.extend_from_slice(b"link");
    main.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    main.extend_from_slice(&payload);
    main.extend_from_slice(&[0u8; 20]);
    (main, shared_index, shared_name)
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
fn a_sparse_directory_entry_restores_a_hidden_project() {
    let dir = repo("sparse-directory");
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\n");
    track(&dir, &["packages/api/"]);

    let unit = scan_repo(&dir);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "a sparse directory entry should restore its project"
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
fn a_tracked_build_directory_is_restored_even_when_ignored() {
    let dir = repo("tracked-build");
    put(&dir, "build/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "build/\n");
    track(&dir, &[".gitignore", "build/.vscode/tasks.json"]);

    let unit = scan_repo(&dir);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "tracked build output stays in the clone and must be scanned: {:?}",
        rules(&unit)
    );
    assert_eq!(unit.findings[0].file, "build/.vscode/tasks.json");
}

#[test]
fn file_names_containing_link_do_not_trigger_split_index_parsing() {
    let dir = repo("link-in-name");
    put(&dir, "linker/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "linker/\n");
    track(&dir, &[".gitignore", "linker/.vscode/tasks.json"]);

    let unit = scan_repo(&dir);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "a normal tracked file path containing 'link' must still be scanned: {:?}",
        rules(&unit)
    );
    assert_eq!(unit.findings[0].file, "linker/.vscode/tasks.json");
}

#[test]
fn real_split_index_with_zero_main_entries_reads_shared_files() {
    let dir = repo("split-zero-main");
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\n");
    let (mut main, shared, shared_name) = split_index(
        &[".gitignore", "packages/api/.vscode/tasks.json"],
        &[],
        &[],
        &[],
    );
    main.truncate(12);
    main[8..12].copy_from_slice(&0u32.to_be_bytes());
    let mut payload = [0x42u8; 20].to_vec();
    payload.extend_from_slice(&ewah(2, &[]));
    payload.extend_from_slice(&ewah(2, &[]));
    main.extend_from_slice(b"link");
    main.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    main.extend_from_slice(&payload);
    main.extend_from_slice(&[0u8; 20]);
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join(".git/index"), main).unwrap();
    fs::write(dir.join(format!(".git/sharedindex.{shared_name}")), shared).unwrap();

    let unit = scan_repo(&dir);
    assert!(rules(&unit).contains(&"vscode/task-run-on-folder-open"));
    assert!(unit.unreadable.is_empty(), "{:#?}", unit.unreadable);
}

#[test]
fn real_split_index_keeps_empty_replacement_names() {
    let dir = repo("split-empty-replacement");
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\n");
    let (main, shared, shared_name) = split_index(
        &[".gitignore", "packages/api/.vscode/tasks.json"],
        &[""],
        &[],
        &[1],
    );
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join(".git/index"), main).unwrap();
    fs::write(dir.join(format!(".git/sharedindex.{shared_name}")), shared).unwrap();

    let unit = scan_repo(&dir);
    assert!(rules(&unit).contains(&"vscode/task-run-on-folder-open"));
    assert!(unit.unreadable.is_empty(), "{:#?}", unit.unreadable);
}

#[test]
fn real_split_index_applies_addition_and_deletion_bitmaps() {
    let dir = repo("split-add-delete");
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, "removed/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\nremoved/\n");
    let (main, shared, shared_name) = split_index(
        &[".gitignore", "removed/.vscode/tasks.json"],
        &["packages/api/.vscode/tasks.json"],
        &[1],
        &[],
    );
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join(".git/index"), main).unwrap();
    fs::write(dir.join(format!(".git/sharedindex.{shared_name}")), shared).unwrap();

    let unit = scan_repo(&dir);
    assert_eq!(
        unit.findings
            .iter()
            .filter(|f| f.rule == "vscode/task-run-on-folder-open")
            .count(),
        1
    );
    assert_eq!(unit.findings[0].file, "packages/api/.vscode/tasks.json");
    assert!(unit.unreadable.is_empty(), "{:#?}", unit.unreadable);
}

#[test]
fn split_index_without_shared_file_is_incomplete() {
    let dir = repo("split-missing-shared");
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\n");
    let (main, _shared, _shared_name) = split_index(
        &[".gitignore", "packages/api/.vscode/tasks.json"],
        &[],
        &[],
        &[],
    );
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join(".git/index"), main).unwrap();

    let unit = scan_repo(&dir);
    assert!(rules(&unit).contains(&"vscode/task-run-on-folder-open"));
    assert!(
        unit.unreadable
            .iter()
            .any(|entry| entry.file == ".git/index")
    );
}

#[test]
fn split_index_overlay_entries_with_empty_names_are_accepted() {
    let dir = repo("split-overlay");
    fs::create_dir_all(dir.join("packages/api/.vscode")).unwrap();
    put(&dir, "packages/api/.vscode/tasks.json", FOLDER_OPEN_TASK);
    put(&dir, ".gitignore", "packages/\n");

    let shared = [0x00u8; 40];
    let shared_entries = [b"packages/api/.vscode/tasks.json"];
    let mut entries = Vec::new();
    for name in shared_entries {
        entries.extend_from_slice(&shared);
        entries.extend_from_slice(&[0x11u8; 20]);
        let name_len = u16::try_from(name.len()).unwrap().min(0xFFF);
        entries.extend_from_slice(&name_len.to_be_bytes());
        entries.extend_from_slice(name);
        entries.push(0);
        let used = entries.len();
        entries.resize(used.next_multiple_of(8), 0);
    }

    let mut shared_index = Vec::from(*b"DIRC");
    shared_index.extend_from_slice(&2u32.to_be_bytes());
    shared_index.extend_from_slice(&u32::try_from(1).unwrap().to_be_bytes());
    shared_index.extend_from_slice(&entries);
    shared_index.extend_from_slice(&[0u8; 20]);

    let hash = [
        0x9eu8, 0x59, 0xc2, 0x40, 0x47, 0x6a, 0xb8, 0x4f, 0x59, 0xb2, 0x5f, 0x1d, 0x26, 0x85, 0x6f,
        0xf0, 0x6b, 0xea, 0x8b, 0xc9,
    ];
    let mut overlay = Vec::from(*b"DIRC");
    overlay.extend_from_slice(&2u32.to_be_bytes());
    overlay.extend_from_slice(&2u32.to_be_bytes());
    overlay.extend_from_slice(&[0u8; 40]);
    overlay.extend_from_slice(&[0x11u8; 20]);
    overlay.extend_from_slice(&0u16.to_be_bytes());
    overlay.push(0);
    overlay.resize(overlay.len().next_multiple_of(8), 0);
    overlay.extend_from_slice(&[0u8; 40]);
    overlay.extend_from_slice(&[0x11u8; 20]);
    overlay.extend_from_slice(&0u16.to_be_bytes());
    overlay.push(0);
    overlay.resize(overlay.len().next_multiple_of(8), 0);
    overlay.extend_from_slice(&[0u8; 20]);

    let mut link = hash.to_vec();
    link.extend_from_slice(&[0u8; 8]);
    link.extend_from_slice(&[0u8; 8]);
    let mut payload = Vec::new();
    payload.extend_from_slice(&link);
    payload.extend_from_slice(&[0u8; 8]);
    payload.extend_from_slice(&[0u8; 8]);
    let mut ext = Vec::from(*b"link");
    ext.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    ext.extend_from_slice(&payload);
    overlay.extend_from_slice(&ext);

    let shared_name = hex_name(&hash);
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join(".git/index"), overlay).unwrap();
    fs::write(
        dir.join(format!(".git/sharedindex.{shared_name}")),
        shared_index,
    )
    .unwrap();

    let unit = scan_repo(&dir);
    assert!(
        rules(&unit).contains(&"vscode/task-run-on-folder-open"),
        "split-index overlays with empty names must recover the shared entry: {:?}",
        rules(&unit)
    );
}

#[test]
fn depth_zero_skips_index_reading_for_root_only_scans() {
    let dir = repo("depth0-index");
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join(".git/index"), b"not an index").unwrap();
    put(&dir, "package.json", "{}");

    let unit = scan(
        &dir,
        &ScanOptions {
            max_depth: 0,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        unit.findings.is_empty(),
        "root-only scans must not fail on an unreadable index: {:#?}",
        unit.unreadable
    );
    assert!(
        unit.unreadable.is_empty(),
        "depth 0 must suppress unreadable index noise: {:#?}",
        unit.unreadable
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
