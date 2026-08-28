//! Python build and interpreter startup surfaces.

use super::{Ctx, Scanner};
use crate::finding::{Finding, ScanUnit, Severity};
use walkdir::WalkDir;

pub struct Python;

impl Scanner for Python {
    fn id(&self) -> &'static str {
        "python"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();
        scan_code_file(
            ctx,
            &mut unit,
            "setup.py",
            "python/setup-script",
            "Python build/install script",
            Severity::Immediate,
            "A setup.py file is Python code evaluated by legacy and compatibility build paths.",
        );
        scan_pyproject(ctx, &mut unit);
        scan_code_file(
            ctx,
            &mut unit,
            "sitecustomize.py",
            "python/sitecustomize",
            "imported by Python site initialization",
            Severity::Deferred,
            "Can be imported automatically during Python site initialization when the project is on the import path.",
        );
        scan_conftest(ctx, &mut unit);
        unit
    }
}

fn meaningful(source: &str) -> Option<&str> {
    source
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
}

fn scan_code_file(
    ctx: &Ctx,
    unit: &mut ScanUnit,
    rel: &str,
    rule: &'static str,
    trigger: &'static str,
    severity: Severity,
    note: &'static str,
) {
    let Some(source) = ctx.read(rel, unit) else {
        return;
    };
    if let Some(preview) = meaningful(&source) {
        unit.push(Finding::new(rule, rel, trigger, preview, severity, note));
    } else {
        unit.clear(rel);
    }
}

fn scan_pyproject(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = "pyproject.toml";
    let Some(source) = ctx.read(rel, unit) else {
        return;
    };
    let doc: toml::Value = match toml::from_str(&source) {
        Ok(doc) => doc,
        Err(e) => {
            unit.mark_unreadable(rel, format!("not parseable as TOML: {e}"));
            return;
        }
    };
    let before = unit.findings.len();
    if let Some(build) = doc.get("build-system").and_then(toml::Value::as_table) {
        let backend = build.get("build-backend").and_then(toml::Value::as_str);
        let paths = build.get("backend-path").and_then(toml::Value::as_array);
        if let (Some(backend), Some(paths)) = (backend, paths) {
            if !backend.trim().is_empty() && !paths.is_empty() {
                let paths = paths
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                unit.push(Finding::new("python/local-build-backend", rel, "local build backend",
                    format!("backend = {backend}; path = [{paths}]") , Severity::Immediate,
                    "The build frontend imports this repository-local backend during build or installation."));
            }
        }
    }
    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn scan_conftest(ctx: &Ctx, unit: &mut ScanUnit) {
    const SKIP: &[&str] = &[
        ".git",
        "target",
        "node_modules",
        "vendor",
        "build",
        "dist",
        ".venv",
        "venv",
        "__pycache__",
    ];
    for entry in WalkDir::new(&ctx.root)
        .follow_links(false)
        .max_depth(12)
        .into_iter()
        .filter_entry(|e| e.file_name().to_str().is_none_or(|n| !SKIP.contains(&n)))
        .flatten()
    {
        if !entry.file_type().is_file() || entry.file_name() != "conftest.py" {
            continue;
        }
        let rel = ctx.rel(entry.path());
        let Some(source) = ctx.read(&rel, unit) else {
            continue;
        };
        if let Some(preview) = meaningful(&source) {
            unit.push(Finding::new(
                "python/pytest-conftest",
                &rel,
                "imported by pytest",
                preview,
                Severity::Deferred,
                "Pytest imports conftest.py during test collection.",
            ));
        } else {
            unit.clear(rel);
        }
    }
}
