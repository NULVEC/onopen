//! `--sarif` checked against the real SARIF 2.1.0 schema.
//!
//! SARIF is the format that puts findings on the diff in GitHub's Security tab.
//! A document GitHub rejects is a scan nobody sees, and the rejection arrives as
//! a failed upload in a log rather than as anything a reviewer notices — so the
//! failure mode is once again silence, and once again it looks like a clean
//! repository.
//!
//! `tests/schema/sarif-2.1.0.json` is the OASIS schema, unedited. The checker
//! below is deliberately small: it resolves `$ref` and enforces `type`,
//! `enum`, `required` and `additionalProperties` over the document onopen
//! actually emits. It does **not** implement all of JSON Schema.
//!
//! What keeps that from being false confidence is the last rule: a schema
//! keyword the checker cannot evaluate is reported as a failure, never skipped.
//! A validator that quietly ignores what it does not understand is the same bug
//! this whole project is about.

use serde_json::Value;
use std::process::Command;

const SCHEMA: &str = include_str!("schema/sarif-2.1.0.json");

/// Keywords that can decide validity on their own and that this checker does
/// not implement. Meeting one along the path the document actually takes means
/// it can no longer speak for the schema, and it says so instead of passing.
///
/// `anyOf` is handled rather than listed here: SARIF uses it for "a message
/// carries text or an id" and "a location has an address or an artifact", which
/// is exactly the branch semantics below.
const UNSUPPORTED: &[&str] = &["allOf", "oneOf", "not", "patternProperties"];

fn resolve<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let pointer = reference.trim_start_matches('#');
            root.pointer(pointer)
                .unwrap_or_else(|| panic!("schema reference {reference} does not resolve"))
        }
        None => schema,
    }
}

fn type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn validate(value: &Value, schema: &Value, root: &Value, path: &str, errors: &mut Vec<String>) {
    let schema = resolve(schema, root);
    let Some(map) = schema.as_object() else {
        return;
    };

    for keyword in UNSUPPORTED {
        if map.contains_key(*keyword) {
            errors.push(format!(
                "{path}: schema uses `{keyword}`, which this checker cannot evaluate"
            ));
            return;
        }
    }

    // Draft-04 `anyOf` sits alongside the other keywords: every one of them
    // still has to hold, and at least one branch has to validate as well.
    if let Some(branches) = map.get("anyOf").and_then(Value::as_array) {
        let satisfied = branches.iter().any(|branch| {
            let mut branch_errors = Vec::new();
            validate(value, branch, root, path, &mut branch_errors);
            branch_errors.is_empty()
        });
        if !satisfied {
            errors.push(format!(
                "{path}: satisfies none of the {} alternatives the schema allows",
                branches.len()
            ));
            return;
        }
    }

    if let Some(expected) = map.get("type").and_then(Value::as_str) {
        if !type_matches(value, expected) {
            errors.push(format!("{path}: expected {expected}, found {value}"));
            return;
        }
    }

    if let Some(allowed) = map.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            errors.push(format!("{path}: {value} is not one of {allowed:?}"));
        }
    }

    if let Some(object) = value.as_object() {
        for required in map
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(name) = required.as_str() {
                if !object.contains_key(name) {
                    errors.push(format!("{path}: missing required property `{name}`"));
                }
            }
        }

        let properties = map.get("properties").and_then(Value::as_object);
        let closed = map.get("additionalProperties") == Some(&Value::Bool(false));

        for (name, child) in object {
            match properties.and_then(|p| p.get(name)) {
                Some(child_schema) => {
                    validate(child, child_schema, root, &format!("{path}.{name}"), errors)
                }
                None if closed => errors.push(format!(
                    "{path}: property `{name}` is not allowed by the schema"
                )),
                None => {}
            }
        }
    }

    if let (Some(items), Some(schema_items)) = (value.as_array(), map.get("items")) {
        for (index, item) in items.iter().enumerate() {
            validate(
                item,
                schema_items,
                root,
                &format!("{path}[{index}]"),
                errors,
            );
        }
    }
}

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
