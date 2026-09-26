//! SARIF output, so findings land in GitHub's Security tab.
//!
//! This is the difference between a tool someone runs once and a tool that
//! stays in a pipeline. A SARIF upload puts each finding on the line of the
//! file it came from, in the review a person is already reading, instead of
//! in log output nobody opens.
//!
//! Suppressed findings are emitted too, carrying SARIF's own `suppressions`
//! marker. Dropping them here would undo in the machine format the guarantee
//! the human format makes: that an ignore file can hide a finding from the
//! report but never from the count.

use crate::finding::{Finding, Severity, Unreadable};
use crate::report::Report;
use crate::visible::visible;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFO_URI: &str = "https://veltron.cc/onopen";

/// A file the scan could not read is not a detection — it is the absence of
/// one. It still belongs in the document: the Security tab is where a reviewer
/// would otherwise never learn that a config file in this diff went unread, and
/// a review that does not know what it missed is the one this tool exists to
/// prevent.
const UNREADABLE_RULE: &str = "onopen/unreadable-config";
const UNREADABLE_NOTE: &str = concat!(
    "This configuration file exists and onopen could not read it. ",
    "The editor or agent that opens this repository may parse it anyway, ",
    "so what it contains is unknown rather than harmless."
);

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Immediate => "error",
        Severity::Deferred => "warning",
        Severity::Note => "note",
    }
}

/// One SARIF rule per rule id that actually appears, described by the note the
/// scanners already carry. Emitting the full catalogue instead would list rules
/// this run never looked for.
fn rules(report: &Report) -> Vec<Value> {
    let mut seen: BTreeMap<&str, &Finding> = BTreeMap::new();
    for finding in report.findings.iter().chain(report.suppressed.iter()) {
        seen.entry(finding.rule).or_insert(finding);
    }

    let mut rules: Vec<Value> = seen
        .into_iter()
        .map(|(id, example)| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": example.note },
                "fullDescription": { "text": example.note },
                "defaultConfiguration": { "level": level(example.severity) },
                "helpUri": INFO_URI,
            })
        })
        .collect();

    if !report.unreadable.is_empty() {
        rules.push(json!({
            "id": UNREADABLE_RULE,
            "name": UNREADABLE_RULE,
            "shortDescription": { "text": "Configuration file could not be read" },
            "fullDescription": { "text": UNREADABLE_NOTE },
            "defaultConfiguration": { "level": "error" },
            "helpUri": INFO_URI,
        }));
    }

    rules
}

/// A relative path as the URI reference SARIF requires.
///
/// Every byte that may not appear raw in an RFC 3986 path is percent-encoded;
/// the `/` separator, unreserved characters and the sub-delimiters and `@`
/// that a path segment allows are kept. Written raw, a file named `a#b` or
/// `x?y` points a strict consumer at a fragment or a query, a first segment
/// with a colon in it reads as a scheme (so `:` is always encoded), and a
/// right-to-left override in a directory name reorders the path a reviewer
/// sees next to the finding. Keeping every character a path may hold raw means
/// the paths of 0.5.x (`node_modules/@scope/x`, `c++/a(1).json`) come out
/// byte for byte the same, so code scanning keeps matching earlier alerts.
/// Encoded, the path is still exact: decoding it gives back the bytes of the
/// name, which is what a consumer matching it against the checkout does.
fn uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        let sub_delim = matches!(
            byte,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        );
        if unreserved || sub_delim || matches!(byte, b'@' | b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn unreadable_result(entry: &Unreadable) -> Value {
    json!({
        "ruleId": UNREADABLE_RULE,
        "level": "error",
        "message": { "text": format!("not read: {}", visible(&entry.reason)) },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri(&entry.file) },
            }
        }],
    })
}

/// `message.text` is what code scanning shows a reviewer, so repository text in
/// it is escaped the way the terminal report escapes it; a right-to-left
/// override in a command must not reorder what the reviewer reads. The
/// `uri` is the exact path, percent-encoded (see [`uri`]).
fn result(finding: &Finding, suppressed: bool) -> Value {
    let mut value = json!({
        "ruleId": finding.rule,
        "level": level(finding.severity),
        "message": {
            "text": format!("{} — {}", visible(&finding.trigger), visible(&finding.command)),
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri(&finding.file) },
            }
        }],
    });

    if suppressed {
        // `external` is the honest kind: the decision lives in .onopenignore,
        // not in the scanned file.
        value["suppressions"] = json!([{
            "kind": "external",
            "justification": "silenced by .onopenignore",
        }]);
    }

    value
}

pub fn render(report: &Report) -> String {
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| result(f, false))
        .chain(report.suppressed.iter().map(|f| result(f, true)))
        .chain(report.unreadable.iter().map(unreadable_result))
        .collect();

    let document = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "onopen",
                    "version": report.version,
                    "informationUri": INFO_URI,
                    "rules": rules(report),
                }
            },
            "results": results,
        }],
    });

    serde_json::to_string_pretty(&document).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::ScanUnit;

    fn finding(rule: &'static str, file: &str, severity: Severity) -> Finding {
        Finding::new(rule, file, "trigger", "command", severity, "why it runs")
    }

    fn report_with(findings: Vec<Finding>, suppressed: Vec<Finding>) -> Report {
        Report::build(
            "/repo".into(),
            ScanUnit {
                findings,
                suppressed,
                ..Default::default()
            },
        )
    }

    fn parse(report: &Report) -> Value {
        serde_json::from_str(&render(report)).expect("SARIF output must be valid JSON")
    }

    #[test]
    fn maps_severity_onto_sarif_levels() {
        let doc = parse(&report_with(
            vec![
                finding("a/immediate", "x.json", Severity::Immediate),
                finding("b/deferred", "y.json", Severity::Deferred),
                finding("c/note", "z.json", Severity::Note),
            ],
            vec![],
        ));
        let levels: Vec<&str> = doc["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        assert!(levels.contains(&"error"));
        assert!(levels.contains(&"warning"));
        assert!(levels.contains(&"note"));
    }

    #[test]
    fn silenced_findings_are_reported_as_suppressed_not_dropped() {
        let doc = parse(&report_with(
            vec![finding("a/kept", "x.json", Severity::Immediate)],
            vec![finding("b/silenced", "y.json", Severity::Immediate)],
        ));
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "both must appear");

        let silenced = results
            .iter()
            .find(|r| r["ruleId"] == "b/silenced")
            .expect("the silenced finding must still be in the document");
        assert_eq!(silenced["suppressions"][0]["kind"], "external");

        let kept = results.iter().find(|r| r["ruleId"] == "a/kept").unwrap();
        assert!(
            kept.get("suppressions").is_none(),
            "a reported finding carries no suppression"
        );
    }

    #[test]
    fn declares_only_the_rules_this_run_used() {
        let doc = parse(&report_with(
            vec![
                finding("a/one", "x.json", Severity::Immediate),
                finding("a/one", "y.json", Severity::Immediate),
            ],
            vec![],
        ));
        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1, "one rule, twice triggered");
        assert_eq!(rules[0]["id"], "a/one");
    }

    #[test]
    fn uris_are_percent_encoded_and_decode_to_the_exact_path() {
        assert_eq!(uri(".vscode/tasks.json"), ".vscode/tasks.json");
        assert_eq!(uri("my dir/a#b?c.json"), "my%20dir/a%23b%3Fc.json");
        assert_eq!(uri("c:x/100%.json"), "c%3Ax/100%25.json");
        assert_eq!(uri("pkg\u{202e}x/t.json"), "pkg%E2%80%AEx/t.json");
        assert_eq!(uri("a[1]\\b.json"), "a%5B1%5D%5Cb.json");
    }

    #[test]
    fn uris_of_plain_ascii_paths_are_unchanged_from_0_5() {
        for path in [
            ".vscode/tasks.json",
            "node_modules/@scope/pkg/package.json",
            "c++/a(1).json",
            "we!rd$&'*+,;=/x_y-z~.toml",
        ] {
            assert_eq!(uri(path), path);
        }
    }

    #[test]
    fn a_clean_scan_is_still_a_valid_document() {
        let doc = parse(&report_with(vec![], vec![]));
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
