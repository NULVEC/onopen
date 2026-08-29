//! Editor configuration outside VS Code.
//!
//! Three editors let a repository decide what runs, and none of them is
//! covered by the `vscode` scanner. JetBrains launches shared startup tasks
//! when a project opens and runs File Watchers when a file changes. Emacs
//! evaluates Lisp from a directory-local file. Vim reads a project-local rc,
//! though only when the user has opted in.
//!
//! What these have in common, and why they are worth a rule while Gradle and
//! Makefiles are not, is that they are files whose whole purpose is to make
//! something run. A repository that ships `.idea/startupTasks.xml` has a
//! startup task; there is no ordinary case to confuse it with. A `Makefile`
//! runs commands too, and reporting every one of them would fire on nearly
//! every repository — which teaches people to skip the output, and then the
//! scanner detects nothing at all.

use super::{Ctx, Scanner};
use crate::finding::{Finding, ScanUnit, Severity};

pub struct Editors;

/// Project-local Vim configuration, in the names Vim and Neovim actually read.
const VIM_RC_FILES: &[&str] = &[".exrc", ".vimrc", ".nvimrc", ".nvim.lua"];

impl Scanner for Editors {
    fn id(&self) -> &'static str {
        "editors"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();
        scan_jetbrains_startup(ctx, &mut unit);
        scan_jetbrains_watchers(ctx, &mut unit);
        scan_emacs_dir_locals(ctx, &mut unit);
        scan_vim_rc(ctx, &mut unit);
        unit
    }
}

/// `.idea/startupTasks.xml` names run configurations JetBrains starts when the
/// project is opened. The file exists for no other reason.
fn scan_jetbrains_startup(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".idea/startupTasks.xml";
    // The same rule the JSON path follows: a file that exists and could not be
    // read is never reported as clean. JetBrains is more forgiving than a
    // strict XML parser, so one we cannot parse is one we cannot speak for.
    let Some(text) = ctx.read(rel, unit) else {
        return;
    };
    let document = match roxmltree::Document::parse(&text) {
        Ok(document) => document,
        Err(e) => {
            unit.mark_unreadable(rel, format!("not parseable as XML: {e}"));
            return;
        }
    };

    let before = unit.findings.len();
    for node in document.descendants() {
        // The list entries carry the configuration name in `value`; the
        // wrapping `<option name="startupTasks">` carries a `name` instead, so
        // keying on `value` alone keeps the wrapper out of the report.
        let Some(name) = node.attribute("value") else {
            continue;
        };
        if name.trim().is_empty() {
            continue;
        }
        // Resolved before the push: both borrow `unit`, and the command is the
        // more useful thing to show, so it is worth the extra line.
        let command =
            resolve_run_configuration(ctx, name, unit).unwrap_or_else(|| name.to_string());
        unit.push(Finding::new(
            "jetbrains/startup-task",
            rel,
            "startup task",
            command,
            Severity::Immediate,
            "JetBrains runs this configuration when the project is opened.",
        ));
    }

    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

/// Follow a startup task to the configuration it names, so the report can show
/// what actually runs instead of only what it is called.
fn resolve_run_configuration(ctx: &Ctx, name: &str, unit: &mut ScanUnit) -> Option<String> {
    let rel = format!(".idea/runConfigurations/{}.xml", name.replace(' ', "_"));
    if !ctx.exists(&rel) {
        return None;
    }
    let text = ctx.read(&rel, unit)?;
    let document = match roxmltree::Document::parse(&text) {
        Ok(document) => document,
        Err(e) => {
            unit.mark_unreadable(&rel, format!("not parseable as XML: {e}"));
            return None;
        }
    };
    let mut parts = Vec::new();
    for node in document.descendants() {
        let key = node.attribute("name").unwrap_or_default();
        if matches!(
            key,
            "SCRIPT_NAME" | "PROGRAM" | "COMMAND" | "EXECUTABLE" | "INTERPRETER_PATH"
        ) {
            if let Some(value) = node.attribute("value") {
                parts.push(value.to_string());
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("{name} — {}", parts.join(" ")))
    }
}

/// File Watchers run a program every time a matching file changes. That needs
/// somebody to edit a file, which is a deliberate act, so it is deferred — but
/// it is an act nobody thinks of as running anything.
fn scan_jetbrains_watchers(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".idea/watcherTasks.xml";
    let Some(text) = ctx.read(rel, unit) else {
        return;
    };
    let document = match roxmltree::Document::parse(&text) {
        Ok(document) => document,
        Err(e) => {
            unit.mark_unreadable(rel, format!("not parseable as XML: {e}"));
            return;
        }
    };

    let before = unit.findings.len();
    for task in document
        .descendants()
        .filter(|n| n.has_tag_name("TaskOptions"))
    {
        if task.attribute("isEnabled") == Some("false") {
            continue;
        }
        let option = |key: &str| {
            task.descendants()
                .find(|n| n.attribute("name") == Some(key))
                .and_then(|n| n.attribute("value"))
                .unwrap_or_default()
                .to_string()
        };

        let program = option("program");
        if program.is_empty() {
            continue;
        }
        let arguments = option("arguments");
        let command = if arguments.is_empty() {
            program
        } else {
            format!("{program} {arguments}")
        };

        let name = task
            .descendants()
            .find(|n| n.attribute("name") == Some("name"))
            .and_then(|n| n.attribute("value"))
            .unwrap_or("unnamed");

        unit.push(Finding::new(
            "jetbrains/file-watcher",
            rel,
            format!("file watcher: {name}"),
            command,
            Severity::Deferred,
            "Runs the configured program whenever a matching file changes.",
        ));
    }

    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

/// `.dir-locals.el` sets variables for every file in the directory, and an
/// `eval` entry is Lisp that Emacs evaluates on visiting one.
///
/// Emacs asks before applying a variable it does not consider safe, and `eval`
/// is never safe, so a prompt stands in the way — which is what keeps this
/// deferred rather than immediate. It is also a prompt that appears while
/// somebody is opening a file, which is when a prompt gets dismissed.
fn scan_emacs_dir_locals(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".dir-locals.el";
    let Some(text) = ctx.read(rel, unit) else {
        return;
    };

    // Only the `eval` entry runs code. The rest of the file sets variables, and
    // reporting those would fire on the ordinary use of the feature.
    let evaluates = text
        .lines()
        .map(|line| line.split(';').next().unwrap_or_default())
        .any(|code| code.contains("(eval ") || code.contains("(eval\t") || code.contains("eval ."));

    if !evaluates {
        unit.clear(rel);
        return;
    }

    unit.push(Finding::new(
        "emacs/directory-local-eval",
        rel,
        "eval entry",
        first_meaningful_line(&text),
        Severity::Deferred,
        "Emacs evaluates this Lisp when a file in the directory is visited.",
    ));
}

/// A project-local Vim rc only runs when the reader has set `exrc`, which is
/// off by default. That makes it a note: it executes nothing on its own, and
/// reporting it as more would fire on a setting the repository does not
/// control.
fn scan_vim_rc(ctx: &Ctx, unit: &mut ScanUnit) {
    for rel in VIM_RC_FILES {
        let Some(text) = ctx.read(rel, unit) else {
            continue;
        };
        if text.trim().is_empty() {
            unit.clear(*rel);
            continue;
        }
        unit.push(Finding::new(
            "vim/project-rc",
            *rel,
            "project-local rc",
            first_meaningful_line(&text),
            Severity::Note,
            "Vim reads this from the working directory, but only with `exrc` enabled.",
        ));
    }
}

/// The first line that is not blank or a comment — usually the first thing the
/// file actually does.
fn first_meaningful_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with(';') && !line.starts_with('"'))
        .unwrap_or("(empty)")
        .to_string()
}
