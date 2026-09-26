//! A small JSON Schema checker shared by the schema tests.
//!
//! It resolves local `$ref` and enforces `type`, `enum`, `required`,
//! `properties`, `additionalProperties: false`, `items` and `anyOf` over the
//! document onopen actually emits. It does **not** implement all of JSON
//! Schema, and a keyword it cannot evaluate is reported as a failure, never
//! skipped: a validator that quietly ignores what it does not understand is
//! the same bug this whole project is about.

#![allow(dead_code)]

use serde_json::Value;

/// Keywords that can decide validity on their own and that this checker does
/// not implement. Meeting one along the path the document actually takes means
/// it can no longer speak for the schema, and it says so instead of passing.
///
/// `anyOf` is handled rather than listed here: SARIF uses it for "a message
/// carries text or an id" and "a location has an address or an artifact", which
/// is exactly the branch semantics below.
pub const UNSUPPORTED: &[&str] = &["allOf", "oneOf", "not", "patternProperties"];

pub fn resolve<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let pointer = reference.trim_start_matches('#');
            root.pointer(pointer)
                .unwrap_or_else(|| panic!("schema reference {reference} does not resolve"))
        }
        None => schema,
    }
}

pub fn type_matches(value: &Value, expected: &str) -> bool {
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

pub fn validate(value: &Value, schema: &Value, root: &Value, path: &str, errors: &mut Vec<String>) {
    walk(value, schema, root, path, false, errors);
}

/// As [`validate`], but every object the schema describes is treated as closed:
/// a property the schema does not name is an error. For onopen's own schema,
/// which stays open so consumers survive added fields, this is what proves the
/// schema documents everything the tool actually prints.
pub fn validate_closed(
    value: &Value,
    schema: &Value,
    root: &Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    walk(value, schema, root, path, true, errors);
}

fn walk(
    value: &Value,
    schema: &Value,
    root: &Value,
    path: &str,
    strict: bool,
    errors: &mut Vec<String>,
) {
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
            walk(value, branch, root, path, strict, &mut branch_errors);
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
        let closed = (strict && properties.is_some())
            || map.get("additionalProperties") == Some(&Value::Bool(false));

        for (name, child) in object {
            match properties.and_then(|p| p.get(name)) {
                Some(child_schema) => walk(
                    child,
                    child_schema,
                    root,
                    &format!("{path}.{name}"),
                    strict,
                    errors,
                ),
                None if closed => errors.push(format!(
                    "{path}: property `{name}` is not allowed by the schema"
                )),
                None => {}
            }
        }
    }

    if let (Some(items), Some(schema_items)) = (value.as_array(), map.get("items")) {
        for (index, item) in items.iter().enumerate() {
            walk(
                item,
                schema_items,
                root,
                &format!("{path}[{index}]"),
                strict,
                errors,
            );
        }
    }
}
