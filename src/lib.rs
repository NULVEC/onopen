//! onopen — see what runs when you open a repository.
//!
//! The library half. It reads and parses configuration files and returns the
//! execution paths it found. It never executes what it finds and never opens a
//! network connection.
//!
//! ```no_run
//! use onopen::{scan, ScanOptions};
//! use std::path::Path;
//!
//! let unit = scan(Path::new("."), &ScanOptions::default())?;
//! println!("{} findings", unit.findings.len());
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod discover;
pub mod finding;
pub mod jsonc;
pub mod report;
pub mod scanners;

use anyhow::{Result, bail};
use finding::ScanUnit;
use scanners::Ctx;
use std::path::Path;

/// How much of the tree to read and which scanners to run.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Empty means every scanner.
    pub only: Vec<String>,
    pub skip: Vec<String>,
    /// How many directories below the root to look for sub-projects.
    /// 0 inspects the root alone, which is what versions before 0.2 did.
    pub max_depth: usize,
}

/// Deep enough for the workspace layouts people actually use
/// (`packages/<name>`, `apps/<name>/<sub>`) without walking a whole disk.
pub const DEFAULT_MAX_DEPTH: usize = 6;

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            only: Vec::new(),
            skip: Vec::new(),
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

/// Ids of every registered scanner, in the order they run.
pub fn scanner_ids() -> Vec<&'static str> {
    scanners::all().iter().map(|s| s.id()).collect()
}

/// Inspect `root` and return everything the scanners found.
pub fn scan(root: &Path, opts: &ScanOptions) -> Result<ScanUnit> {
    if !root.is_dir() {
        bail!("{} is not a directory", root.display());
    }

    let registry = scanners::all();
    let known: Vec<&'static str> = registry.iter().map(|s| s.id()).collect();
    for requested in opts.only.iter().chain(opts.skip.iter()) {
        if !known.contains(&requested.as_str()) {
            bail!(
                "unknown scanner {requested:?}; available: {}",
                known.join(", ")
            );
        }
    }

    let selected: Vec<&Box<dyn scanners::Scanner>> = registry
        .iter()
        .filter(|s| opts.only.is_empty() || opts.only.iter().any(|o| o == s.id()))
        .filter(|s| !opts.skip.iter().any(|k| k == s.id()))
        .collect();

    let mut unit = ScanUnit::default();

    for unit_dir in discover::scan_units(root, opts.max_depth) {
        let ctx = Ctx::new(&unit_dir);
        // Paths come back relative to the sub-project, so they get the
        // sub-project's own path put back in front of them.
        let prefix = unit_dir
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
            .unwrap_or_default();

        for scanner in &selected {
            let mut found = scanner.scan(&ctx);
            found.prefix_paths(&prefix);
            unit.merge(found);
        }
    }

    Ok(unit)
}
