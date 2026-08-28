//! Git hooks.
//!
//! Hooks in `.git/hooks` are not carried by a clone, which is why they get
//! dismissed. But `core.hooksPath` moves the hook directory into the working
//! tree, and every "run this one setup command" README turns a checked-in
//! directory into live hooks.

use super::{Ctx, Scanner};
use crate::finding::{Finding, ScanUnit, Severity};
use walkdir::WalkDir;
use yaml_rust2::{Yaml, YamlLoader};

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
        scan_pre_commit(ctx, &mut unit);
        unit
    }
}

/// `core.hooksPath` redirects hooks to a directory that can live in the repo.
fn scan_config(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".git/config";
    let Some(text) = ctx.read(rel, unit) else {
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
        let rel = ctx.rel(entry.path());
        let preview = ctx
            .read(&rel, unit)
            .and_then(|text| first_meaningful_line(&text))
            .unwrap_or_else(|| "(unreadable)".into());
        unit.push(Finding::new(
            "git/active-hook",
            rel,
            format!("git hook: {name}"),
            preview,
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
            let rel = ctx.rel(entry.path());
            let preview = ctx
                .read(&rel, unit)
                .and_then(|text| first_meaningful_line(&text))
                .unwrap_or_else(|| "(unreadable)".into());
            unit.push(Finding::new(
                "git/checked-in-hook",
                rel,
                format!("hook script: {name}"),
                preview,
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
fn first_meaningful_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("#!"))
        .map(ToOwned::to_owned)
}

fn yget<'a>(value: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    value.as_hash()?.get(&Yaml::String(key.into()))
}

fn scan_pre_commit(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".pre-commit-config.yaml";
    let Some(source) = ctx.read(rel, unit) else {
        return;
    };
    let doc = match YamlLoader::load_from_str(&source) {
        Ok(mut docs) if !docs.is_empty() => docs.remove(0),
        Ok(_) => {
            unit.clear(rel);
            return;
        }
        Err(e) => {
            unit.mark_unreadable(rel, format!("not parseable as YAML: {e}"));
            return;
        }
    };
    let before = unit.findings.len();
    for repo in yget(&doc, "repos")
        .and_then(Yaml::as_vec)
        .into_iter()
        .flatten()
    {
        let local_repo = yget(repo, "repo").and_then(Yaml::as_str) == Some("local");
        for hook in yget(repo, "hooks")
            .and_then(Yaml::as_vec)
            .into_iter()
            .flatten()
        {
            let system = yget(hook, "language").and_then(Yaml::as_str) == Some("system");
            if !local_repo && !system {
                continue;
            }
            let Some(entry) = yget(hook, "entry")
                .and_then(Yaml::as_str)
                .filter(|s| !s.trim().is_empty())
            else {
                continue;
            };
            let id = yget(hook, "id").and_then(Yaml::as_str).unwrap_or("unnamed");
            unit.push(Finding::new(
                "git/pre-commit-local-entry",
                rel,
                format!("local hook: {id}"),
                entry,
                Severity::Deferred,
                "Pre-commit can install this repository-defined command as a local hook.",
            ));
        }
    }
    if unit.findings.len() == before {
        unit.clear(rel);
    }
}
