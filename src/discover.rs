//! Finding the directories worth scanning.
//!
//! A repository is rarely one project. Monorepos put a `package.json` and a
//! `.vscode/` in every workspace, and a hostile task buried three levels down
//! fires the moment someone opens that folder. Scanning only the top directory
//! reports those repositories clean, which for a security tool is the worst
//! failure available: a silent false negative.

use ignore::WalkBuilder;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A directory is worth scanning if it holds any of these. They are exactly the
/// files and directories the scanners know how to read, so a unit that matches
/// none of them has nothing for us to find.
const PROJECT_MARKERS: &[&str] = &[
    ".vscode",
    ".idea",
    ".dir-locals.el",
    ".exrc",
    ".claude",
    ".cursor",
    ".gemini",
    ".devcontainer",
    ".devcontainer.json",
    ".mcp.json",
    ".githooks",
    ".husky",
    ".cargo",
    ".yarnrc.yml",
    ".pnpmfile.cjs",
    ".pnpmfile.mjs",
    ".envrc",
    ".mise.toml",
    "mise.toml",
    "shell.nix",
    "flake.nix",
    "pyproject.toml",
    "setup.py",
    "sitecustomize.py",
    "conftest.py",
    "Cargo.toml",
    "pnpm-workspace.yaml",
    ".pre-commit-config.yaml",
    "package.json",
    "composer.json",
    "Gemfile",
];

/// Directories that never contain a project of the user's own. `.gitignore`
/// covers most of these in a well-kept repository, but not in every one, and a
/// scan that wanders into `node_modules` is both slow and useless — those are
/// dependencies, not the project being opened.
const ALWAYS_SKIP: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "out",
    "coverage",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".gradle",
    "Pods",
];

/// Every directory under `root` that looks like a project, including `root`
/// itself, sorted so a run over the same tree always reports in the same order.
///
/// `max_depth` counts directories below the root; 0 means the root only.
pub fn scan_units(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut units: BTreeSet<PathBuf> = BTreeSet::new();
    // The root is always scanned, marker or not: the caller asked for it, and
    // reporting nothing because a repository keeps its config elsewhere would
    // be surprising.
    units.insert(root.to_path_buf());

    if max_depth == 0 {
        return units.into_iter().collect();
    }

    let walker = WalkBuilder::new(root)
        // `.vscode` and `.claude` are hidden directories and are the whole
        // point of this tool, so hidden entries have to stay in.
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .parents(false)
        .follow_links(false)
        .max_depth(Some(max_depth + 1))
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !ALWAYS_SKIP.contains(&name))
                .unwrap_or(true)
        })
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !entry.file_type().is_some_and(|t| t.is_dir()) {
            continue;
        }
        if path == root {
            continue;
        }
        if has_marker(path) {
            units.insert(path.to_path_buf());
        }
    }

    units.into_iter().collect()
}

fn has_marker(dir: &Path) -> bool {
    PROJECT_MARKERS
        .iter()
        .any(|marker| dir.join(marker).exists())
        || std::fs::read_dir(dir).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(".code-workspace"))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("onopen-discover-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn root_is_always_a_unit_even_without_markers() {
        let root = tmp("bare");
        assert_eq!(scan_units(&root, 4), vec![root]);
    }

    #[test]
    fn finds_nested_projects() {
        let root = tmp("nested");
        fs::create_dir_all(root.join("packages/api/.vscode")).unwrap();
        fs::write(root.join("packages/api/.vscode/tasks.json"), "{}").unwrap();
        fs::create_dir_all(root.join("packages/web")).unwrap();
        fs::write(root.join("packages/web/package.json"), "{}").unwrap();

        let units = scan_units(&root, 8);
        assert!(units.contains(&root.join("packages/api")));
        assert!(units.contains(&root.join("packages/web")));
        // `packages/` itself holds no marker of its own.
        assert!(!units.contains(&root.join("packages")));
    }

    #[test]
    fn skips_dependency_directories() {
        let root = tmp("deps");
        fs::create_dir_all(root.join("node_modules/evil")).unwrap();
        fs::write(root.join("node_modules/evil/package.json"), "{}").unwrap();

        let units = scan_units(&root, 8);
        assert_eq!(units, vec![root]);
    }

    #[test]
    fn depth_zero_scans_only_the_root() {
        let root = tmp("depth0");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/package.json"), "{}").unwrap();

        assert_eq!(scan_units(&root, 0), vec![root.clone()]);
        assert!(scan_units(&root, 1).contains(&root.join("sub")));
    }
}
