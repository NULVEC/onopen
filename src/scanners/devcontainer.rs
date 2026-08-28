//! Dev container definitions.
//!
//! Most of these commands run inside the container, which is at least a
//! boundary. `initializeCommand` is the exception: it runs on the host, before
//! the container exists.

use super::{Ctx, Scanner, command_text};
use crate::finding::{Finding, ScanUnit, Severity};
use serde_json::Value;
use walkdir::WalkDir;

pub struct DevContainer;

/// Lifecycle hooks, paired with whether they run on the host.
const LIFECYCLE: &[(&str, bool)] = &[
    ("initializeCommand", true),
    ("onCreateCommand", false),
    ("updateContentCommand", false),
    ("postCreateCommand", false),
    ("postStartCommand", false),
    ("postAttachCommand", false),
];

impl Scanner for DevContainer {
    fn id(&self) -> &'static str {
        "devcontainer"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();

        for rel in locate(ctx) {
            let Some(doc) = ctx.json(&rel, &mut unit) else {
                continue;
            };
            let before = unit.findings.len();

            for (key, on_host) in LIFECYCLE {
                let Some(cmd) = doc.get(*key).and_then(command_text) else {
                    continue;
                };
                if *on_host {
                    unit.push(Finding::new(
                        "devcontainer/host-initialize-command",
                        rel.clone(),
                        (*key).to_string(),
                        cmd,
                        Severity::Immediate,
                        "Runs on the host machine, outside the container boundary.",
                    ));
                } else {
                    unit.push(Finding::new(
                        "devcontainer/container-lifecycle-command",
                        rel.clone(),
                        (*key).to_string(),
                        cmd,
                        Severity::Deferred,
                        "Runs inside the container when it is created or started.",
                    ));
                }
            }

            // Features are OCI artifacts that ship their own install scripts.
            if let Some(features) = doc.get("features").and_then(Value::as_object) {
                for name in features.keys() {
                    unit.push(Finding::new(
                        "devcontainer/feature",
                        rel.clone(),
                        "features",
                        name.clone(),
                        Severity::Note,
                        "Dev container features run their own install script on build.",
                    ));
                }
            }

            if unit.findings.len() == before {
                unit.clear(rel.clone());
            }
        }

        unit
    }
}

/// Dev containers live in three places, including one nested layout for repos
/// that define several.
fn locate(ctx: &Ctx) -> Vec<String> {
    let mut found = Vec::new();

    for rel in [".devcontainer.json", ".devcontainer/devcontainer.json"] {
        if ctx.exists(rel) {
            found.push(rel.to_string());
        }
    }

    let nested = ctx.path(".devcontainer");
    if nested.is_dir() {
        for entry in WalkDir::new(&nested)
            .max_depth(2)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry.file_name() == "devcontainer.json" {
                let rel = ctx.rel(entry.path());
                if !found.contains(&rel) {
                    found.push(rel);
                }
            }
        }
    }

    found
}
