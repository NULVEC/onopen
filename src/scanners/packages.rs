//! Package manifests: npm, Composer, Bundler.
//!
//! The oldest execution path on the list and still the most productive one.
//! Included because the question is "what runs when I open this", and for most
//! repositories the first thing anyone does after opening is install.

use super::{Ctx, Scanner, command_text};
use crate::finding::{Finding, ScanUnit, Severity};
use serde_json::Value;
use yaml_rust2::{Yaml, YamlLoader};

pub struct Packages;

/// npm lifecycle scripts that run as part of a plain `npm install`.
const NPM_INSTALL_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

/// npm scripts that run on other common actions.
const NPM_DEFERRED_SCRIPTS: &[&str] = &[
    "prepack",
    "postpack",
    "prepublish",
    "prepublishOnly",
    "postpublish",
    "preuninstall",
    "postuninstall",
];

/// Composer scripts that fire on install or update.
const COMPOSER_SCRIPTS: &[&str] = &[
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "post-autoload-dump",
    "post-root-package-install",
    "post-create-project-cmd",
];

/// Ruby constructs that shell out. A Gemfile is executable Ruby, not data.
const RUBY_EXEC_MARKERS: &[(&str, &str)] = &[
    ("system(", "system()"),
    ("`", "backtick shell"),
    ("%x(", "%x()"),
    ("IO.popen", "IO.popen"),
    ("Open3.", "Open3"),
    ("exec(", "exec()"),
    ("eval(", "eval()"),
    ("require_relative", "require_relative"),
];

impl Scanner for Packages {
    fn id(&self) -> &'static str {
        "packages"
    }

    fn scan(&self, ctx: &Ctx) -> ScanUnit {
        let mut unit = ScanUnit::default();
        scan_npm(ctx, &mut unit);
        scan_composer(ctx, &mut unit);
        scan_gemfile(ctx, &mut unit);
        scan_pnpmfile(ctx, &mut unit);
        scan_yarn(ctx, &mut unit);
        scan_pnpm_workspace(ctx, &mut unit);
        unit
    }
}

fn meaningful_module(source: &str) -> Option<&str> {
    source.lines().map(str::trim).find(|line| {
        !line.is_empty()
            && !line.starts_with("//")
            && !line.starts_with("/*")
            && !line.starts_with('*')
    })
}

fn scan_pnpmfile(ctx: &Ctx, unit: &mut ScanUnit) {
    for rel in [".pnpmfile.cjs", ".pnpmfile.mjs"] {
        let Some(source) = ctx.read(rel, unit) else {
            continue;
        };
        if let Some(preview) = meaningful_module(&source) {
            unit.push(Finding::new(
                "pnpm/pnpmfile-hook",
                rel,
                "pnpm hook module",
                preview,
                Severity::Immediate,
                "Pnpm loads this repository module during dependency resolution and installation.",
            ));
        } else {
            unit.clear(rel);
        }
    }
}

fn yaml(ctx: &Ctx, unit: &mut ScanUnit, rel: &str) -> Option<Yaml> {
    let source = ctx.read(rel, unit)?;
    match YamlLoader::load_from_str(&source) {
        Ok(mut docs) if !docs.is_empty() => Some(docs.remove(0)),
        Ok(_) => {
            unit.clear(rel);
            None
        }
        Err(e) => {
            unit.mark_unreadable(rel, format!("not parseable as YAML: {e}"));
            None
        }
    }
}

fn yget<'a>(value: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    value.as_hash()?.get(&Yaml::String(key.into()))
}

fn scan_yarn(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = ".yarnrc.yml";
    let Some(doc) = yaml(ctx, unit, rel) else {
        return;
    };
    let before = unit.findings.len();
    if let Some(path) = yget(&doc, "yarnPath")
        .and_then(Yaml::as_str)
        .filter(|s| !s.trim().is_empty())
    {
        unit.push(Finding::new(
            "yarn/yarn-path",
            rel,
            "yarnPath",
            path,
            Severity::Immediate,
            "Yarn loads the project-supplied Yarn binary when it starts.",
        ));
    }
    for plugin in yget(&doc, "plugins")
        .and_then(Yaml::as_vec)
        .into_iter()
        .flatten()
    {
        let Some(path) = yget(plugin, "path").and_then(Yaml::as_str) else {
            continue;
        };
        if path.trim().is_empty() || path.contains("://") {
            continue;
        }
        let spec = yget(plugin, "spec")
            .and_then(Yaml::as_str)
            .unwrap_or("local plugin");
        unit.push(Finding::new(
            "yarn/local-plugin",
            rel,
            format!("plugin: {spec}"),
            path,
            Severity::Immediate,
            "Yarn loads this repository-local JavaScript plugin when it starts.",
        ));
    }
    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn yaml_nonempty(value: &Yaml) -> bool {
    match value {
        Yaml::Boolean(v) => *v,
        Yaml::Array(v) => !v.is_empty(),
        Yaml::Hash(v) => !v.is_empty(),
        Yaml::String(v) => !v.trim().is_empty(),
        _ => false,
    }
}

fn scan_pnpm_workspace(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = "pnpm-workspace.yaml";
    let Some(doc) = yaml(ctx, unit, rel) else {
        return;
    };
    let before = unit.findings.len();
    for key in [
        "dangerouslyAllowAllBuilds",
        "allowBuilds",
        "onlyBuiltDependencies",
    ] {
        let Some(value) = yget(&doc, key).filter(|v| yaml_nonempty(v)) else {
            continue;
        };
        unit.push(Finding::new(
            "pnpm/dependency-build-approval",
            rel,
            key,
            yaml_preview(value),
            Severity::Note,
            "This setting pre-approves dependency build scripts that pnpm can execute during install.",
        ));
    }
    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn yaml_preview(value: &Yaml) -> String {
    match value {
        Yaml::Boolean(value) => value.to_string(),
        Yaml::String(value) => value.clone(),
        Yaml::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(yaml_preview)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Yaml::Hash(values) => format!("{} approved package(s)", values.len()),
        other => format!("{other:?}"),
    }
}

fn scan_npm(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = "package.json";
    let Some(doc) = ctx.json(rel, unit) else {
        return;
    };
    let before = unit.findings.len();

    if let Some(scripts) = doc.get("scripts").and_then(Value::as_object) {
        for (name, body) in scripts {
            let Some(cmd) = command_text(body) else {
                continue;
            };

            if NPM_INSTALL_SCRIPTS.contains(&name.as_str()) {
                unit.push(Finding::new(
                    "npm/install-lifecycle-script",
                    rel,
                    name.clone(),
                    cmd,
                    Severity::Immediate,
                    "Runs during `npm install`, before any of your own code does.",
                ));
            } else if NPM_DEFERRED_SCRIPTS.contains(&name.as_str()) {
                unit.push(Finding::new(
                    "npm/other-lifecycle-script",
                    rel,
                    name.clone(),
                    cmd,
                    Severity::Deferred,
                    "Runs on pack, publish or uninstall rather than on install.",
                ));
            }
        }
    }

    // Dependencies resolved straight from a URL bypass the registry entirely,
    // so nothing about them is pinned or auditable by version.
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(deps) = doc.get(field).and_then(Value::as_object) else {
            continue;
        };
        for (name, spec) in deps {
            let Some(spec) = spec.as_str() else { continue };
            let direct = spec.starts_with("git+")
                || spec.starts_with("http://")
                || spec.starts_with("https://")
                || spec.starts_with("file:")
                || spec.starts_with("github:");
            if direct {
                unit.push(Finding::new(
                    "npm/dependency-from-url",
                    rel,
                    format!("{field}: {name}"),
                    spec,
                    Severity::Note,
                    "Fetched outside the registry, so no published version pins it.",
                ));
            }
        }
    }

    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn scan_composer(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = "composer.json";
    let Some(doc) = ctx.json(rel, unit) else {
        return;
    };
    let before = unit.findings.len();

    if let Some(scripts) = doc.get("scripts").and_then(Value::as_object) {
        for (name, body) in scripts {
            if !COMPOSER_SCRIPTS.contains(&name.as_str()) {
                continue;
            }
            let Some(cmd) = command_text(body) else {
                continue;
            };
            unit.push(Finding::new(
                "composer/lifecycle-script",
                rel,
                name.clone(),
                cmd,
                Severity::Immediate,
                "Runs during `composer install` or `composer update`.",
            ));
        }
    }

    if unit.findings.len() == before {
        unit.clear(rel);
    }
}

fn scan_gemfile(ctx: &Ctx, unit: &mut ScanUnit) {
    let rel = "Gemfile";
    let Some(source) = ctx.read(rel, unit) else {
        return;
    };
    let before = unit.findings.len();

    for (line_no, line) in source.lines().enumerate() {
        let code = line.split('#').next().unwrap_or(line);
        if code.trim().is_empty() {
            continue;
        }
        for (marker, label) in RUBY_EXEC_MARKERS {
            if code.contains(marker) {
                unit.push(Finding::new(
                    "bundler/gemfile-executes-ruby",
                    rel,
                    format!("line {} — {label}", line_no + 1),
                    code.trim(),
                    Severity::Immediate,
                    "A Gemfile is evaluated as Ruby by every bundler command.",
                ));
                break;
            }
        }
    }

    if unit.findings.len() == before {
        unit.clear(rel);
    }
}
