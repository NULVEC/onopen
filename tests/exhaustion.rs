//! Small files that cost far more than their size.
//!
//! Every config is capped at 8 MiB before it is parsed (see `hostile.rs`).
//! What is left is what a parser does with the bytes it is given: nesting that
//! recurses once per level, and YAML aliases that copy what they point at. A
//! scan that aborts on a stack overflow or runs out of memory prints nothing at
//! all — no finding, no "incomplete", not even an exit code of 2.
//!
//! Every scan here runs on a 1 MiB stack, which is what Windows gives the main
//! thread of the shipped binary. Test threads get more, and a limit that only
//! holds on a test thread does not hold.

use onopen::finding::ScanUnit;
use onopen::{ScanOptions, scan};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DEPTH: usize = 100_000;

fn fresh(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onopen-exhaust-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn scan_on_main_thread_stack(dir: &Path) -> ScanUnit {
    let dir = dir.to_path_buf();
    std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(move || scan(&dir, &ScanOptions::default()).expect("the repository still scans"))
        .unwrap()
        .join()
        .expect("the scan must return, not abort")
}

/// Write one hostile file, scan, and hold the result to the rule: reported
/// unreadable, with a reason that says why, in bounded time and length.
fn assert_refused(name: &str, rel: &str, body: String, contains: &str) {
    let dir = fresh(name);
    let path = dir.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, body).unwrap();

    let started = Instant::now();
    let unit = scan_on_main_thread_stack(&dir);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{name} took {:?}",
        started.elapsed()
    );

    let entry = unit
        .unreadable
        .iter()
        .find(|u| u.file == rel)
        .unwrap_or_else(|| panic!("{rel} must be reported unreadable, got {unit:?}"));
    assert!(
        entry.reason.contains(contains),
        "reason was {:?}, expected it to mention {contains:?}",
        entry.reason
    );
    assert!(
        entry.reason.chars().count() <= 400,
        "a reason must not carry the file with it: {} chars",
        entry.reason.chars().count()
    );
    assert!(!unit.cleared.iter().any(|c| c == rel));
}

#[test]
fn deeply_nested_xml_is_refused_instead_of_overflowing_the_stack() {
    // About a thousand levels were enough to abort the process on Windows.
    assert_refused(
        "xml-deep",
        ".idea/startupTasks.xml",
        format!(
            "<project>{}{}</project>",
            "<a>".repeat(DEPTH),
            "</a>".repeat(DEPTH)
        ),
        "nested past",
    );
}

#[test]
fn a_yaml_billion_laughs_is_refused_before_it_is_expanded() {
    // Under a kilobyte; ten billion nodes once the aliases are copied.
    let mut s = String::from("a0: &a0 [lol,lol,lol,lol,lol,lol,lol,lol,lol,lol]\n");
    for i in 1..10 {
        let prev = format!("*a{}", i - 1);
        s.push_str(&format!("a{i}: &a{i} [{}]\n", vec![prev; 10].join(",")));
    }
    s.push_str("repos: *a9\n");
    assert_refused(
        "yaml-laughs",
        ".pre-commit-config.yaml",
        s.clone(),
        "billion laughs",
    );
    assert_refused(
        "yaml-laughs-pnpm",
        "pnpm-workspace.yaml",
        s,
        "billion laughs",
    );
}

#[test]
fn deeply_nested_yaml_is_refused() {
    assert_refused(
        "yaml-deep",
        ".pre-commit-config.yaml",
        format!("repos: {}{}", "[".repeat(DEPTH), "]".repeat(DEPTH)),
        "not parseable as YAML",
    );
}

#[test]
fn deeply_nested_toml_is_refused_with_a_bounded_reason() {
    // `toml` quotes the line it failed on, and here the line is the file.
    assert_refused(
        "toml-deep",
        "Cargo.toml",
        format!(
            "[package]\nname = \"x\"\nx = {}{}\n",
            "[".repeat(DEPTH),
            "]".repeat(DEPTH)
        ),
        "not parseable as TOML",
    );
    assert_refused(
        "toml-deep-inline",
        "pyproject.toml",
        format!("x = {}{}\n", "{a=".repeat(DEPTH), "}".repeat(DEPTH)),
        "not parseable as TOML",
    );
}

#[test]
fn deeply_nested_json_is_refused_on_the_main_thread_stack() {
    assert_refused(
        "json-deep",
        ".vscode/settings.json",
        format!("{}{}", "[".repeat(DEPTH), "]".repeat(DEPTH)),
        "not parseable as JSON",
    );
}

#[test]
fn one_enormous_line_under_the_size_limit_is_read() {
    // Size is the limit, not shape: a 7 MiB single line is still a file some
    // editor will open, and it gets scanned like any other.
    let dir = fresh("huge-line");
    fs::create_dir_all(dir.join(".vscode")).unwrap();
    let label = "x".repeat(7 * 1024 * 1024);
    fs::write(
        dir.join(".vscode/tasks.json"),
        format!(
            r#"{{"tasks":[{{"label":"{label}","command":"node ./setup.js","runOptions":{{"runOn":"folderOpen"}}}}]}}"#
        ),
    )
    .unwrap();

    let unit = scan_on_main_thread_stack(&dir);
    assert!(unit.unreadable.is_empty(), "got {:?}", unit.unreadable);
    let finding = unit
        .findings
        .iter()
        .find(|f| f.rule == "vscode/task-run-on-folder-open")
        .expect("the task is still found");
    assert!(finding.trigger.chars().count() < 1000);
}
