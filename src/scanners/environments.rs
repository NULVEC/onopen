//! Repository-local shell environment hooks.

use super::{Ctx, Scanner};
use crate::finding::{Finding, ScanUnit, Severity};

pub struct Environments;

impl Scanner for Environments {
    fn id(&self) -> &'static str {
        "environments"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();
        scan_script(
            ctx,
            &mut unit,
            ".envrc",
            "direnv/environment-script",
            "direnv load after allow",
            Severity::Deferred,
            "Direnv evaluates this shell file only after its content has been explicitly allowed.",
        );
        for rel in ["mise.toml", ".mise.toml"] {
            scan_mise(ctx, &mut unit, rel);
        }
        for rel in ["shell.nix", "flake.nix"] {
            scan_nix(ctx, &mut unit, rel);
        }
        unit
    }
}

fn meaningful(source: &str) -> Option<&str> {
    source
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
}

fn scan_script(
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
    if let Some(line) = meaningful(&source) {
        unit.push(Finding::new(rule, rel, trigger, line, severity, note));
    } else {
        unit.clear(rel);
    }
}

fn scan_mise(ctx: &Ctx, unit: &mut ScanUnit, rel: &str) {
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
    if let Some(hooks) = doc.get("hooks").and_then(toml::Value::as_table) {
        for name in ["enter", "cd", "leave", "preinstall", "postinstall"] {
            if let Some(value) = hooks.get(name) {
                let severity = if name == "leave" {
                    Severity::Deferred
                } else {
                    Severity::Immediate
                };
                for command in mise_commands(value) {
                    unit.push(Finding::new("mise/automatic-hook", rel, format!("hook {name}"), command, severity,
                        "Mise runs this lifecycle hook from an activated shell or install operation."));
                }
            }
        }
    }
    for watch in doc
        .get("watch_files")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(table) = watch.as_table() {
            for key in ["run", "task"] {
                if let Some(value) = table.get(key) {
                    for command in mise_commands(value) {
                        unit.push(Finding::new(
                            "mise/watch-file-hook",
                            rel,
                            format!("watch_files {key}"),
                            command,
                            Severity::Deferred,
                            "Mise can run this after a watched file changes.",
                        ));
                    }
                }
            }
        }
    }
    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn mise_commands(value: &toml::Value) -> Vec<String> {
    match value {
        toml::Value::String(s) if !s.trim().is_empty() => vec![s.clone()],
        toml::Value::Array(a) => a.iter().flat_map(mise_commands).collect(),
        toml::Value::Table(t) => ["run", "task"]
            .iter()
            .filter_map(|k| t.get(*k))
            .flat_map(mise_commands)
            .collect(),
        _ => Vec::new(),
    }
}

fn scan_nix(ctx: &Ctx, unit: &mut ScanUnit, rel: &str) {
    let Some(source) = ctx.read(rel, unit) else {
        return;
    };
    let before = unit.findings.len();
    let lines: Vec<_> = source.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let code = line.split('#').next().unwrap_or("");
        let Some((_, rhs)) = code.split_once("shellHook") else {
            continue;
        };
        let Some((_, rhs)) = rhs.split_once('=') else {
            continue;
        };
        let preview = meaningful(rhs)
            .or_else(|| lines.iter().skip(i + 1).take(8).find_map(|l| meaningful(l)))
            .unwrap_or("shellHook expression");
        unit.push(Finding::new("nix/shell-hook", rel, "shellHook", preview, Severity::Deferred,
            "Nix evaluates this hook after the developer deliberately enters the development shell."));
    }
    if unit.findings.len() == before {
        unit.clear(rel);
    }
}
