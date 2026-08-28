//! Cargo build scripts and executable overrides.

use super::{Ctx, Scanner};
use crate::finding::{Finding, ScanUnit, Severity};

pub struct Cargo;

impl Scanner for Cargo {
    fn id(&self) -> &'static str {
        "cargo"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();
        scan_manifest(ctx, &mut unit);
        for rel in [".cargo/config.toml", ".cargo/config"] {
            scan_config(ctx, &mut unit, rel);
        }
        unit
    }
}

fn parse(ctx: &Ctx, unit: &mut ScanUnit, rel: &str) -> Option<toml::Value> {
    let source = ctx.read(rel, unit)?;
    match toml::from_str(&source) {
        Ok(doc) => Some(doc),
        Err(e) => {
            unit.mark_unreadable(rel, format!("not parseable as TOML: {e}"));
            None
        }
    }
}

fn scan_manifest(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = "Cargo.toml";
    let Some(doc) = parse(ctx, unit, rel) else {
        return;
    };
    let before = unit.findings.len();
    let build = doc
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("build"));
    let command = match build {
        Some(toml::Value::Boolean(false)) => None,
        Some(toml::Value::String(path)) if !path.trim().is_empty() => Some(path.clone()),
        Some(toml::Value::Boolean(true)) => Some("build.rs".into()),
        None if ctx.exists("build.rs") => Some("build.rs".into()),
        _ => None,
    };
    if let Some(command) = command {
        unit.push(Finding::new(
            "cargo/build-script",
            rel,
            "package build script",
            command,
            Severity::Deferred,
            "Cargo executes the package build script before a deliberate build.",
        ));
    }
    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn scan_config(ctx: &Ctx, unit: &mut ScanUnit, rel: &str) {
    let Some(doc) = parse(ctx, unit, rel) else {
        return;
    };
    let before = unit.findings.len();
    if let Some(build) = doc.get("build").and_then(toml::Value::as_table) {
        for key in [
            "rustc",
            "rustc-wrapper",
            "rustc-workspace-wrapper",
            "rustdoc",
        ] {
            push_value(unit, rel, &format!("build.{key}"), build.get(key));
        }
    }
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for (triple, config) in targets {
            if let Some(config) = config.as_table() {
                for key in ["runner", "linker"] {
                    push_value(
                        unit,
                        rel,
                        &format!("target.{triple}.{key}"),
                        config.get(key),
                    );
                }
            }
        }
    }
    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn push_value(unit: &mut ScanUnit, rel: &str, key: &str, value: Option<&toml::Value>) {
    let command = match value {
        Some(toml::Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        Some(toml::Value::Array(a)) if !a.is_empty() => Some(
            a.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    };
    if let Some(command) = command {
        unit.push(Finding::new(
            "cargo/compiler-wrapper",
            rel,
            key,
            command,
            Severity::Deferred,
            "Cargo spawns this configured executable during a deliberate build or run command.",
        ));
    }
}
