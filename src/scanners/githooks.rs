//! Git hooks.
//!
//! Hooks in `.git/hooks` are not carried by a clone, which is why they get
//! dismissed. But `core.hooksPath` moves the hook directory into the working
//! tree, and every "run this one setup command" README turns a checked-in
//! directory into live hooks.

use super::{Ctx, Scanner};
use crate::finding::{Finding, ScanUnit, Severity};
use walkdir::WalkDir;

pub struct GitHooks;

/// Directories a repository ships hooks in, expecting them to be wired up.
const CHECKED_IN_HOOK_DIRS: &[&str] = &[".githooks", ".husky", ".hooks"];

impl Scanner for GitHooks {
    fn id(&self) -> &'static str {
        "githooks"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();
        scan_config(ctx, &mut unit);
        scan_active_hooks(ctx, &mut unit);
        scan_checked_in(ctx, &mut unit);
        unit
    }
}

/// `core.hooksPath` redirects hooks to a directory that can live in the repo.
fn scan_config(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".git/config";
    let Some(text) = ctx.read(rel) else {
        return;
    };

    for line in text.lines() {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("hookspath") {
            unit.push(Finding::new(
                "git/hooks-path-redirected",
                rel,
                "core.hooksPath",
                value.trim(),
                Severity::Immediate,
                "Git hooks are read from this path, which can be inside the repository.",
            ));
        }
    }
}

/// Live hooks in `.git/hooks`. Git ships `.sample` files there, which never run.
fn scan_active_hooks(ctx: &Ctx, unit: &mut ScanUnit) {
    let dir = ctx.path(".git/hooks");
    if !dir.is_dir() {
        return;
    }

    for entry in WalkDir::new(&dir)
        .max_depth(1)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".sample") {
            continue;
        }
        unit.push(Finding::new(
            "git/active-hook",
            ctx.rel(entry.path()),
            format!("git hook: {name}"),
            first_meaningful_line(entry.path()),
            Severity::Immediate,
            "Runs on the matching git operation in this clone right now.",
        ));
    }
}

/// Hook scripts committed to the working tree, waiting to be wired up.
fn scan_checked_in(ctx: &Ctx, unit: &mut ScanUnit) {
    for dir_name in CHECKED_IN_HOOK_DIRS {
        let dir = ctx.path(dir_name);
        if !dir.is_dir() {
            continue;
        }

        let mut found_any = false;
        for entry in WalkDir::new(&dir)
            .max_depth(2)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') || name.ends_with(".md") {
                continue;
            }
            found_any = true;
            unit.push(Finding::new(
                "git/checked-in-hook",
                ctx.rel(entry.path()),
                format!("hook script: {name}"),
                first_meaningful_line(entry.path()),
                Severity::Deferred,
                "Becomes live once core.hooksPath or a setup step points git at it.",
            ));
        }

        if !found_any {
            unit.clear((*dir_name).to_string());
        }
    }
}

/// Show the first line that is not a shebang, comment or blank — usually the
/// first thing the hook actually does.
fn first_meaningful_line(path: &std::path::Path) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return "(unreadable)".into();
    };
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("#!"))
        .unwrap_or("(no statements)")
        .to_string()
}
