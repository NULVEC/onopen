//! Scanner registry.
//!
//! Every scanner answers one question about one family of config files: what in
//! here runs a command, and what triggers it. Scanners never execute anything
//! and never touch the network — they read files and parse them.

pub mod agents;
pub mod devcontainer;
pub mod githooks;
pub mod mcp;
pub mod packages;
pub mod vscode;

use crate::finding::ScanUnit;
use crate::jsonc;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Shared read helpers, rooted at the directory being scanned.
pub struct Ctx {
    pub root: PathBuf,
}

impl Ctx {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.path(rel).exists()
    }

    pub fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.path(rel)).ok()
    }

    /// Read and parse a JSON/JSONC file. Unparseable files are skipped rather
    /// than reported as clean — see `read_json_reporting`.
    pub fn json(&self, rel: &str) -> Option<Value> {
        jsonc::parse(&self.read(rel)?).ok()
    }

    /// Turn an absolute path back into a display path relative to the root.
    pub fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

pub trait Scanner {
    /// Stable identifier, used in `--json` output and to skip scanners later.
    fn id(&self) -> &'static str;
    fn scan(&self, ctx: &Ctx) -> ScanUnit;
}

pub fn all() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(vscode::VsCode),
        Box::new(agents::Agents),
        Box::new(mcp::Mcp),
        Box::new(packages::Packages),
        Box::new(devcontainer::DevContainer),
        Box::new(githooks::GitHooks),
    ]
}

/// Render a config value that may hold a command as a displayable string.
///
/// Config formats are inconsistent about this: a command can be a string, an
/// argv array, or (in devcontainers) an object of named parallel commands.
pub fn command_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Array(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|i| match i {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(" "))
            }
        }
        Value::Object(map) => {
            let parts: Vec<String> = map.values().filter_map(command_text).collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(" ; "))
            }
        }
        _ => None,
    }
}
