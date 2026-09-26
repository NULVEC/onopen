//! The 1.x contract, as `docs/CONTRACT.md` states it.
//!
//! Scripts, CI jobs and the GitHub Action are written against three things:
//! the exit code, the `--json` document and the `--sarif` document. Each test
//! here pins one sentence of the contract, so a change that would break a
//! consumer fails here first instead of in someone else's pipeline.

mod common;

use common::{validate, validate_closed};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REPORT_SCHEMA: &str = include_str!("../docs/schema/report-v1.json");

const BOOT_TASK: &str = r#"{"tasks":[{"label":"boot","command":"node ./tools/boot.js","runOptions":{"runOn":"folderOpen"}}]}"#;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn repo(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onopen-contract-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn put(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn onopen(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_onopen"))
        .arg(root)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("onopen should run")
}

fn json(root: &Path) -> Value {
    let output = onopen(root, &["--json"]);
    serde_json::from_slice(&output.stdout).expect("--json must emit valid JSON")
}

/// A repository that exercises every part of the report at once: a finding, a
/// silenced finding, an unreadable file and an ignore line that matches nothing.
fn everything() -> PathBuf {
    let root = repo("everything");
    put(&root, ".vscode/tasks.json", BOOT_TASK);
    put(&root, ".vscode/settings.json", "{ this is not json");
    put(
        &root,
        "package.json",
        r#"{"scripts":{"preinstall":"node stage.js"}}"#,
    );
    put(
        &root,
        ".onopenignore",
        "vscode/task-run-on-folder-open  .vscode/tasks.json  # reviewed\nnpm/nothing-by-this-name  nowhere/**\n",
    );
    root
}

fn assert_schema(document: &Value) {
    let schema: Value =
        serde_json::from_str(REPORT_SCHEMA).expect("the report schema should parse");
    let mut errors = Vec::new();
    validate_closed(document, &schema, &schema, "$", &mut errors);
    assert!(
        errors.is_empty(),
        "--json does not match docs/schema/report-v1.json:\n  {}",
        errors.join("\n  ")
    );
}

#[test]
fn the_json_report_matches_its_published_schema() {
    // Closed validation: a field the tool prints and the schema does not name
    // fails here, so the schema cannot fall behind what consumers receive.
    assert_schema(&json(&fixture("trapped")));
    assert_schema(&json(&fixture("clean")));

    let full = json(&everything());
    assert!(!full["findings"].as_array().unwrap().is_empty());
    assert!(!full["suppressed"].as_array().unwrap().is_empty());
    assert!(!full["unreadable"].as_array().unwrap().is_empty());
    assert!(!full["stale_ignore_lines"].as_array().unwrap().is_empty());
    assert_schema(&full);
}

#[test]
fn the_published_schema_stays_open_to_added_fields() {
    // Adding a field is not a breaking change in 1.x, so a consumer validating
    // with the published schema must not start failing when one appears.
    let schema: Value = serde_json::from_str(REPORT_SCHEMA).unwrap();
    let mut document = json(&fixture("trapped"));
    document["added_in_a_later_1x"] = Value::Bool(true);
    document["findings"][0]["also_new"] = Value::from(1);
    let mut errors = Vec::new();
    validate(&document, &schema, &schema, "$", &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn the_json_report_declares_its_schema_and_tool_version() {
    let document = json(&fixture("trapped"));
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["tool"], "onopen");
    assert_eq!(document["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn the_summary_counts_what_the_arrays_carry() {
    let document = json(&everything());
    let summary = &document["summary"];
    let count = |key: &str| document[key].as_array().unwrap().len() as u64;
    let severity = |level: &str| {
        document["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["severity"] == level)
            .count() as u64
    };
    assert_eq!(summary["suppressed"], count("suppressed"));
    assert_eq!(summary["unreadable"], count("unreadable"));
    assert_eq!(summary["immediate"], severity("immediate"));
    assert_eq!(summary["deferred"], severity("deferred"));
    assert_eq!(summary["note"], severity("note"));
}

#[test]
fn exit_codes_do_not_depend_on_the_output_format() {
    let trapped = fixture("trapped");
    let clean = fixture("clean");
    for args in [&[][..], &["--json"], &["--sarif"], &["--quiet"]] {
        assert_eq!(onopen(&trapped, args).status.code(), Some(1), "{args:?}");
        assert_eq!(onopen(&clean, args).status.code(), Some(0), "{args:?}");
    }
}

#[test]
fn an_incomplete_scan_outranks_a_finding() {
    // Findings plus an unreadable file is 2, not 1: the answer is partial, and
    // what the unread file does is unknown. `--no-fail` does not hide it.
    let root = everything();
    assert_eq!(onopen(&root, &["--quiet"]).status.code(), Some(2));
    assert_eq!(
        onopen(&root, &["--quiet", "--no-fail"]).status.code(),
        Some(2)
    );
    assert_eq!(onopen(&root, &["--json"]).status.code(), Some(2));
}

#[test]
fn failures_before_the_scan_exit_2() {
    let missing = std::env::temp_dir().join("onopen-contract-does-not-exist");
    let _ = fs::remove_dir_all(&missing);
    assert_eq!(onopen(&missing, &[]).status.code(), Some(2), "missing path");

    let root = fixture("clean");
    assert_eq!(
        onopen(&root, &["--no-such-flag"]).status.code(),
        Some(2),
        "usage error"
    );
    assert_eq!(
        onopen(&root, &["--only", "nope"]).status.code(),
        Some(2),
        "unknown scanner"
    );
}

#[test]
fn sarif_carries_every_result_kind_the_contract_names() {
    let output = onopen(&everything(), &["--sarif"]);
    let sarif: Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    let unread = results
        .iter()
        .find(|r| r["ruleId"] == "onopen/unreadable-config")
        .expect("an unreadable file is a result");
    assert_eq!(unread["level"], "error");

    let silenced = results
        .iter()
        .find(|r| r.get("suppressions").is_some())
        .expect("a silenced finding stays in the document");
    assert_eq!(silenced["suppressions"][0]["kind"], "external");

    for result in results {
        let uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(!uri.starts_with('/') && !uri.contains('\\'), "{uri}");
    }
}
