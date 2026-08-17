//! Coding-agent configuration: Claude Code, Gemini CLI, Cursor.
//!
//! This is the surface that appeared in the last year and that dependency
//! scanners were never pointed at. A hook in a checked-in `.claude/settings.json`
//! runs a shell command on session start — the agent opens the repo, the hook
//! fires, and nothing was installed.

use super::{Ctx, Scanner, command_text};
use crate::finding::{Finding, ScanUnit, Severity};
use serde_json::Value;

pub struct Agents;

/// Files that configure an agent and can carry a command hook.
const HOOK_FILES: &[&str] = &[
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
    ".cursor/environment.json",
];

impl Scanner for Agents {
    fn id(&self) -> &'static str {
        "agents"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();

        for rel in HOOK_FILES {
            let Some(doc) = ctx.json(rel) else {
                continue;
            };
            let before = unit.findings.len();

            scan_hooks(&doc, rel, &mut unit);
            scan_cursor_env(&doc, rel, &mut unit);
            scan_permissions(&doc, rel, &mut unit);

            if unit.findings.len() == before {
                unit.clear(*rel);
            }
        }

        unit
    }
}

/// Walk the `hooks` tree and report every `{"type":"command","command":"..."}`.
///
/// Walked generically rather than against a fixed schema: the shape of the hooks
/// block has changed more than once, and a scanner that only understands last
/// year's layout silently reports clean.
fn scan_hooks(doc: &Value, rel: &str, unit: &mut ScanUnit) {
    let Some(hooks) = doc.get("hooks") else {
        return;
    };

    match hooks {
        Value::Object(events) => {
            for (event, body) in events {
                collect_commands(body, event, rel, unit);
            }
        }
        other => collect_commands(other, "hooks", rel, unit),
    }
}

fn collect_commands(v: &Value, event: &str, rel: &str, unit: &mut ScanUnit) {
    match v {
        Value::Object(map) => {
            let is_command_hook = map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| t.eq_ignore_ascii_case("command"));

            if is_command_hook {
                if let Some(cmd) = map.get("command").and_then(command_text) {
                    let matcher = map
                        .get("matcher")
                        .and_then(Value::as_str)
                        .filter(|m| !m.is_empty());
                    let trigger = match matcher {
                        Some(m) => format!("hook {event} [{m}]"),
                        None => format!("hook {event}"),
                    };
                    unit.push(Finding::new(
                        "agent/command-hook",
                        rel,
                        trigger,
                        cmd,
                        Severity::Immediate,
                        "Agent hooks run as shell commands without a per-run prompt.",
                    ));
                }
            }

            for (_, child) in map {
                collect_commands(child, event, rel, unit);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_commands(item, event, rel, unit);
            }
        }
        _ => {}
    }
}

/// Cursor background agents run `install` and `start` when the environment boots.
fn scan_cursor_env(doc: &Value, rel: &str, unit: &mut ScanUnit) {
    if !rel.starts_with(".cursor/") {
        return;
    }
    for key in ["install", "start", "build"] {
        if let Some(cmd) = doc.get(key).and_then(command_text) {
            unit.push(Finding::new(
                "agent/cursor-environment-command",
                rel,
                format!("{key} command"),
                cmd,
                Severity::Immediate,
                "Runs when the Cursor background agent environment starts.",
            ));
        }
    }
}

/// A checked-in allowlist that pre-approves shell access is not itself an
/// execution path, but it removes the prompt that would have caught one.
fn scan_permissions(doc: &Value, rel: &str, unit: &mut ScanUnit) {
    let Some(allow) = doc
        .get("permissions")
        .and_then(|p| p.get("allow"))
        .and_then(Value::as_array)
    else {
        return;
    };

    for entry in allow {
        let Some(text) = entry.as_str() else { continue };
        let broad = text == "Bash"
            || text.starts_with("Bash(*")
            || text.contains(":*)")
            || text == "Bash(*)";
        if broad {
            unit.push(Finding::new(
                "agent/broad-permission-allow",
                rel,
                "permissions.allow",
                text,
                Severity::Note,
                "Pre-approves shell commands, removing the prompt that would surface one.",
            ));
        }
    }
}
