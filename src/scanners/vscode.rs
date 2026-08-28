//! VS Code workspace configuration.
//!
//! The headline vector: a task with `runOptions.runOn = "folderOpen"` executes
//! as soon as the folder is trusted, before the developer types anything.
//! `settings.json` is the quieter one — a dozen extensions read an executable
//! path or an override command out of workspace settings and run it on load.

use super::{Ctx, Scanner, command_text};
use crate::finding::{Finding, ScanUnit, Severity};
use serde_json::Value;

pub struct VsCode;

/// Workspace settings keys that hand a path or command to an extension, which
/// then runs it. Matched as suffixes/substrings against the full dotted key.
const EXEC_SETTING_MARKERS: &[&str] = &[
    "executablepath",
    "overridecommand",
    "server.path",
    "serverpath",
    "custompath",
    "toolspath",
    "interpreterpath",
    "defaultinterpreterpath",
    "terminal.integrated.automationprofile",
    "terminal.integrated.shellargs",
    "terminal.integrated.defaultprofile",
    "git.path",
    "npm.packagemanager",
    "rust-analyzer.procmacro.server",
    "rust-analyzer.runnables.command",
    "rust-analyzer.cargo.buildscripts.overridecommand",
];

impl Scanner for VsCode {
    fn id(&self) -> &'static str {
        "vscode"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();
        scan_tasks(ctx, &mut unit);
        scan_workspace_tasks(ctx, &mut unit);
        scan_settings(ctx, &mut unit);
        scan_launch(ctx, &mut unit);
        unit
    }
}

fn scan_workspace_tasks(ctx: &Ctx, unit: &mut ScanUnit) {
    let Ok(entries) = std::fs::read_dir(&ctx.root) else {
        return;
    };
    let mut files = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            name.ends_with(".code-workspace").then_some(name)
        })
        .collect::<Vec<_>>();
    files.sort();

    for rel in files {
        let Some(doc) = ctx.json(&rel, unit) else {
            continue;
        };
        let before = unit.findings.len();
        let tasks = doc
            .get("tasks")
            .and_then(|v| v.get("tasks"))
            .and_then(Value::as_array);
        let Some(tasks) = tasks else {
            unit.clear(rel);
            continue;
        };
        for task in tasks {
            let run_on = task
                .get("runOptions")
                .and_then(|r| r.get("runOn"))
                .and_then(Value::as_str);
            if run_on != Some("folderOpen") {
                continue;
            }
            let label = task
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or("unnamed task");
            let mut command = task_command(task);
            for dependency in dependency_labels(task) {
                if let Some(target) = tasks.iter().find(|candidate| {
                    candidate.get("label").and_then(Value::as_str) == Some(dependency)
                }) {
                    command.push_str(&format!(
                        " ; dependsOn {dependency}: {}",
                        task_command(target)
                    ));
                }
            }
            unit.push(Finding::new(
                "vscode/workspace-task-run-on-folder-open",
                &rel,
                format!("runOn: folderOpen ({label})"),
                command,
                Severity::Immediate,
                "Runs when this trusted multi-root workspace opens.",
            ));
        }
        if unit.findings.len() == before {
            unit.clear(rel);
        }
    }
}

fn dependency_labels(task: &Value) -> Vec<&str> {
    match task.get("dependsOn") {
        Some(Value::String(label)) => vec![label],
        Some(Value::Array(labels)) => labels.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn task_command(task: &Value) -> String {
    let base = command_with_override(task, None);
    let mut variants = Vec::new();
    for os in ["windows", "linux", "osx"] {
        let Some(override_value) = task.get(os) else {
            continue;
        };
        let command = command_with_override(task, Some(override_value));
        if command != "(no command)" {
            variants.push(format!("{os}: {command}"));
        }
    }
    if variants.is_empty() {
        base
    } else {
        format!("{base} [{}]", variants.join("; "))
    }
}

fn command_with_override(task: &Value, platform: Option<&Value>) -> String {
    let cmd = platform
        .and_then(|value| value.get("command"))
        .or_else(|| task.get("command"))
        .and_then(command_text)
        .unwrap_or_else(|| "(no command)".into());
    let args = platform
        .and_then(|value| value.get("args"))
        .or_else(|| task.get("args"))
        .and_then(command_text)
        .unwrap_or_default();
    if args.is_empty() {
        cmd
    } else {
        format!("{cmd} {args}")
    }
}

fn scan_tasks(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".vscode/tasks.json";
    let Some(doc) = ctx.json(rel, unit) else {
        return;
    };

    let before = unit.findings.len();
    let tasks = doc.get("tasks").and_then(Value::as_array);

    for task in tasks.into_iter().flatten() {
        let cmd = task
            .get("command")
            .and_then(command_text)
            .unwrap_or_else(|| "(no command)".into());
        let args = task.get("args").and_then(command_text).unwrap_or_default();
        let full = if args.is_empty() {
            cmd
        } else {
            format!("{cmd} {args}")
        };

        let run_on = task
            .get("runOptions")
            .and_then(|r| r.get("runOn"))
            .and_then(Value::as_str);

        if run_on == Some("folderOpen") {
            let label = task
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or("unnamed task");
            unit.push(Finding::new(
                "vscode/task-run-on-folder-open",
                rel,
                format!("runOn: folderOpen ({label})"),
                full,
                Severity::Immediate,
                "Runs the moment the folder is opened and trusted, with no further action.",
            ));
        }
    }

    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn scan_settings(ctx: &Ctx, unit: &mut ScanUnit) {
    for rel in [".vscode/settings.json", ".cursor/settings.json"] {
        let Some(doc) = ctx.json(rel, unit) else {
            continue;
        };
        let Some(map) = doc.as_object() else {
            continue;
        };

        let before = unit.findings.len();
        for (key, value) in map {
            let lower = key.to_ascii_lowercase();
            if !EXEC_SETTING_MARKERS.iter().any(|m| lower.contains(m)) {
                continue;
            }
            let Some(cmd) = command_text(value) else {
                continue;
            };
            unit.push(Finding::new(
                "vscode/setting-runs-binary",
                rel,
                format!("setting: {key}"),
                cmd,
                Severity::Immediate,
                "Workspace settings can point an extension at a binary it launches on load.",
            ));
        }

        // Environment injected into every terminal the workspace opens.
        for (key, value) in map {
            if !key
                .to_ascii_lowercase()
                .starts_with("terminal.integrated.env.")
            {
                continue;
            }
            if let Some(cmd) = command_text(value) {
                unit.push(Finding::new(
                    "vscode/terminal-env-injection",
                    rel,
                    format!("setting: {key}"),
                    cmd,
                    Severity::Deferred,
                    "Injects environment variables into every terminal opened in this workspace.",
                ));
            }
        }

        if unit.findings.len() == before {
            unit.clear(rel);
        }
    }
}

fn scan_launch(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".vscode/launch.json";
    let Some(doc) = ctx.json(rel, unit) else {
        return;
    };

    let before = unit.findings.len();
    for cfg in doc
        .get("configurations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = cfg.get("name").and_then(Value::as_str).unwrap_or("unnamed");

        if let Some(task) = cfg.get("preLaunchTask").and_then(Value::as_str) {
            unit.push(Finding::new(
                "vscode/pre-launch-task",
                rel,
                format!("preLaunchTask ({name})"),
                task,
                Severity::Deferred,
                "Runs when the developer starts a debug session.",
            ));
        }

        for key in ["program", "runtimeExecutable"] {
            let Some(cmd) = cfg.get(key).and_then(command_text) else {
                continue;
            };
            if !(cmd.contains("${workspaceFolder}") || cmd.starts_with('.')) {
                continue;
            }
            // `program` names the thing being debugged, and pointing it at a
            // source file in the repository is what debugging is — reporting
            // that would fire on nearly every launch.json ever written, which
            // is how a scanner teaches people to ignore it. `runtimeExecutable`
            // is the interpreter that runs it, and a repository supplying its
            // own is the substitution nobody reads.
            if key == "program" && is_interpreted_source(&cmd) {
                continue;
            }
            unit.push(Finding::new(
                "vscode/launch-workspace-binary",
                rel,
                format!("{key} ({name})"),
                cmd,
                Severity::Note,
                "Launches a binary shipped inside the repository.",
            ));
        }
    }

    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

/// Whether a launch target is a source file a debugger interprets rather than
/// an executable the repository ships.
fn is_interpreted_source(path: &str) -> bool {
    const SOURCE_EXTENSIONS: &[&str] = &[
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".php", ".dart", ".lua", ".pl",
    ];
    let lower = path.to_ascii_lowercase();
    SOURCE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}
