//! `--sarif` checked against the real SARIF 2.1.0 schema.
//!
//! SARIF is the format that puts findings on the diff in GitHub's Security tab.
//! A document GitHub rejects is a scan nobody sees, and the rejection arrives as
//! a failed upload in a log rather than as anything a reviewer notices — so the
//! failure mode is once again silence, and once again it looks like a clean
//! repository.
//!
//! `tests/schema/sarif-2.1.0.json` is the OASIS schema, unedited. The checker
//! in `tests/common` is deliberately small and says so: a schema keyword it
//! cannot evaluate is reported as a failure, never skipped.

mod common;

use common::validate;
use serde_json::Value;
use std::process::Command;

const SCHEMA: &str = include_str!("schema/sarif-2.1.0.json");

/// Run onopen over a fixture and parse what `--sarif` printed.
fn sarif_for(fixture: &str, extra: &[&str]) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(fixture);

    let output = Command::new(env!("CARGO_BIN_EXE_onopen"))
        .arg(&root)
        .arg("--sarif")
        .args(extra)
        .env("NO_COLOR", "1")
        .output()
        .expect("onopen should run");

    serde_json::from_slice(&output.stdout).expect("--sarif must emit valid JSON")
}

fn assert_valid(document: &Value) {
    let schema: Value = serde_json::from_str(SCHEMA).expect("the SARIF schema should parse");
    let mut errors = Vec::new();
    validate(document, &schema, &schema, "$", &mut errors);
    assert!(
        errors.is_empty(),
        "SARIF document does not satisfy the 2.1.0 schema:\n  {}",
        errors.join("\n  ")
    );
}

#[test]
fn a_report_with_findings_satisfies_the_schema() {
    assert_valid(&sarif_for("trapped", &[]));
}

#[test]
fn a_clean_report_satisfies_the_schema() {
    assert_valid(&sarif_for("clean", &[]));
}

#[test]
fn the_document_declares_the_version_the_schema_is_for() {
    let document = sarif_for("trapped", &[]);
    assert_eq!(document["version"], "2.1.0");
    assert!(document["runs"][0]["tool"]["driver"]["name"] == "onopen");
}

#[test]
fn every_result_points_at_a_rule_the_document_declares() {
    // GitHub renders a result against its rule. One that names a rule the run
    // never declared shows up with no description at all — technically valid,
    // and useless to the person reading the diff.
    let document = sarif_for("trapped", &[]);
    let run = &document["runs"][0];

    let declared: Vec<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("the driver should declare its rules")
        .iter()
        .map(|rule| rule["id"].as_str().expect("a rule needs an id"))
        .collect();

    for result in run["results"]
        .as_array()
        .expect("results should be an array")
    {
        let id = result["ruleId"].as_str().expect("a result needs a ruleId");
        assert!(
            declared.contains(&id),
            "result names {id}, which the run does not declare: {declared:?}"
        );
    }
}
