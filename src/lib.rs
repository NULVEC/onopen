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

pub mod finding;
pub mod jsonc;
pub mod report;
pub mod scanners;

use anyhow::{Result, bail};
use finding::ScanUnit;
use scanners::Ctx;
use std::path::Path;

/// Which scanners to run. Empty lists mean "all of them".
#[derive(Debug, Default, Clone)]
pub struct ScanOptions {
    pub only: Vec<String>,
    pub skip: Vec<String>,
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

    let ctx = Ctx::new(root);
    let mut unit = ScanUnit::default();

    for scanner in &registry {
        let id = scanner.id();
        if !opts.only.is_empty() && !opts.only.iter().any(|s| s == id) {
            continue;
        }
        if opts.skip.iter().any(|s| s == id) {
            continue;
        }
        unit.merge(scanner.scan(&ctx));
    }

    Ok(unit)
}
