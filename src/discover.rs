//! Finding the directories worth scanning.
//!
//! A repository is rarely one project. Monorepos put a `package.json` and a
//! `.vscode/` in every workspace, and a hostile task buried three levels down
//! fires the moment someone opens that folder. Scanning only the top directory
//! reports those repositories clean, which for a security tool is the worst
//! failure available: a silent false negative.

use crate::finding::Unreadable;
use crate::gitindex::{self, Index};
use ignore::WalkBuilder;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Marker directories: a directory holding one of these is a project, and so is
/// the directory above one of these wherever it turns up in a tracked path.
const DIR_MARKERS: &[&str] = &[
    ".vscode",
    ".idea",
    ".claude",
    ".cursor",
    ".gemini",
    ".windsurf",
    ".continue",
    ".zed",
    ".devcontainer",
    ".githooks",
    ".husky",
    ".cargo",
];

/// Marker files. Each one is a config file some scanner knows how to read.
const FILE_MARKERS: &[&str] = &[
    ".dir-locals.el",
    ".exrc",
    ".devcontainer.json",
    ".mcp.json",
    ".npmrc",
    "bunfig.toml",
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
    "usercustomize.py",
    "noxfile.py",
    "conftest.py",
    "Cargo.toml",
    "pnpm-workspace.yaml",
    ".pre-commit-config.yaml",
    "package.json",
    "composer.json",
    "Gemfile",
    "gems.rb",
    ".aider.conf.yml",
];

/// Directories that are always treated as non-project content on the walk.
/// Build output names are skipped only when they are untracked; a committed
/// config under `build/` or `dist/` is still part of the project and must be
/// restored from the index.
const WALK_SKIP: &[&str] = &[
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

/// Dependency directories that must never be treated as a tracked project,
/// even when they are committed by mistake. The repository's own code is what
/// is being opened, not the dependency tree it happens to contain.
const TRACKED_SKIP: &[&str] = &[".git", "node_modules", "vendor", "Pods"];

/// What one pass over the tree turned up.
pub struct Discovery {
    /// Directories to scan, sorted so a run over the same tree always reports
    /// in the same order.
    pub units: Vec<PathBuf>,
    /// Set when the repository has an index that could not be read. The walk
    /// still happened, but it could not be checked against what is committed,
    /// so the result is a partial answer and has to say so.
    pub unreadable: Option<Unreadable>,
}

/// Every directory under `root` that looks like a project, including `root`
/// itself.
///
/// `max_depth` counts directories below the root; 0 means the root only.
pub fn discover(root: &Path, max_depth: usize) -> Discovery {
    let mut units: BTreeSet<PathBuf> = BTreeSet::new();
    // The root is always scanned, marker or not: the caller asked for it, and
    // reporting nothing because a repository keeps its config elsewhere would
    // be surprising.
    units.insert(root.to_path_buf());

    if max_depth == 0 {
        return Discovery {
            units: units.into_iter().collect(),
            unreadable: None,
        };
    }

    let index = gitindex::read(root);

    // Ignore rules describe what git will not pick up next. They do not describe
    // what a clone contains, and treating them as if they did is only safe
    // because the index is read afterwards to put back what they hid. When the
    // index is the thing we could not read, that check is gone — so the rules
    // stop being trusted rather than being trusted blindly.
    let trust_ignore = !matches!(index, Index::Unreadable(_));

    let walker = WalkBuilder::new(root)
        // `.vscode` and `.claude` are hidden directories and are the whole
        // point of this tool, so hidden entries have to stay in.
        .hidden(false)
        .git_ignore(trust_ignore)
        .git_global(false)
        .git_exclude(trust_ignore)
        .parents(false)
        .follow_links(false)
        .max_depth(Some(max_depth))
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !WALK_SKIP.contains(&name))
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

    // Whatever the walk skipped that is nonetheless committed. A path can only
    // get here by being in the index, so this adds back exactly the directories
    // an ignore rule was hiding from a clone — and nothing else.
    if let Index::Tracked(paths) = &index {
        for tracked in paths {
            let Some(rel) = unit_of(tracked) else {
                continue;
            };
            if rel.is_empty() || rel.split('/').count() > max_depth {
                continue;
            }
            if rel.split('/').any(|part| TRACKED_SKIP.contains(&part)) {
                continue;
            }
            let dir = root.join(&rel);
            // The file is committed; the directory may still have been deleted
            // in this working tree, and there is nothing to read if it was.
            if dir.is_dir() && has_marker(&dir) {
                units.insert(dir);
            }
        }
    }

    Discovery {
        units: units.into_iter().collect(),
        unreadable: index_unreadable(&index),
    }
}

/// Every directory under `root` that looks like a project.
///
/// The short form of [`discover`], for callers that only want the list.
pub fn scan_units(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    discover(root, max_depth).units
}

fn index_unreadable(index: &Index) -> Option<Unreadable> {
    match index {
        Index::Unreadable(reason) => Some(Unreadable {
            file: ".git/index".into(),
            reason: reason.clone(),
        }),
        _ => None,
    }
}

/// The project directory a tracked path belongs to, relative to the repository
/// root, or `None` if the path is not one of the files a scanner reads.
fn unit_of(tracked: &str) -> Option<String> {
    if tracked.ends_with('/') {
        return Some(tracked.trim_end_matches('/').to_string());
    }
    let mut parts: Vec<&str> = tracked.split('/').collect();
    let file = parts.pop()?;

    // A marker directory anywhere along the path names the project above it:
    // `packages/api/.vscode/tasks.json` is `packages/api`.
    if let Some(at) = parts.iter().position(|part| DIR_MARKERS.contains(part)) {
        return Some(parts[..at].join("/"));
    }

    if FILE_MARKERS.contains(&file) || file.ends_with(".code-workspace") {
        return Some(parts.join("/"));
    }

    None
}

fn has_marker(dir: &Path) -> bool {
    DIR_MARKERS
        .iter()
        .chain(FILE_MARKERS)
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
