//! Scanner registry.
//!
//! Every scanner answers one question about one family of config files: what in
//! here runs a command, and what triggers it. Scanners never execute anything
//! and never touch the network — they read files and parse them.

pub mod agents;
pub mod cargo;
pub mod devcontainer;
pub mod editors;
pub mod environments;
pub mod githooks;
pub mod mcp;
pub mod packages;
pub mod python;
pub mod vscode;

use crate::finding::ScanUnit;
use crate::jsonc;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Configuration files are small. Past this, what is on disk is not a config
/// file somebody wrote, and reading it into memory is a denial of service the
/// scanner would be carrying out on itself.
pub const MAX_CONFIG_BYTES: u64 = 8 * 1024 * 1024;

/// What came back from asking for one file.
///
/// The three cases are kept apart on purpose. Collapsing "not there" and
/// "there but unreadable" into a single `None` is what let a byte order mark
/// turn a repository with a `folderOpen` task into a clean report.
enum Source {
    Text(String),
    Absent,
    Unreadable(String),
}

/// Shared read helpers, rooted at the directory being scanned.
pub struct Ctx {
    pub root: PathBuf,
    /// The top of the whole scan. A symlink may point anywhere inside it; one
    /// that leaves it is pointing at something that is not part of the
    /// repository being opened.
    pub scan_root: PathBuf,
}

impl Ctx {
    /// A scan whose root is also the top of the scan.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            scan_root: root.clone(),
            root,
        }
    }

    /// A sub-project inside a larger scan.
    pub fn within(root: impl Into<PathBuf>, scan_root: impl Into<PathBuf>) -> Self {
        let scan_root: PathBuf = scan_root.into();
        Self {
            root: root.into(),
            scan_root: scan_root.canonicalize().unwrap_or(scan_root),
        }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.path(rel).exists()
    }

    /// Read a file as text, recording anything that got in the way.
    ///
    /// Returns `None` both when the file is absent and when it could not be
    /// read, but only the second case leaves a mark on `unit` — and that mark
    /// is what keeps the file out of the clean list.
    pub fn read(&self, rel: &str, unit: &mut ScanUnit) -> Option<String> {
        match self.load(rel) {
            Source::Text(text) => Some(text),
            Source::Absent => None,
            Source::Unreadable(reason) => {
                unit.mark_unreadable(rel, reason);
                None
            }
        }
    }

    /// Read and parse a JSON/JSONC file. A file that does not parse is recorded
    /// as unreadable, never passed over in silence: whatever opens this
    /// repository next may have a more forgiving parser than ours.
    pub fn json(&self, rel: &str, unit: &mut ScanUnit) -> Option<Value> {
        let text = self.read(rel, unit)?;
        match jsonc::parse(&text) {
            Ok(value) => Some(value),
            Err(e) => {
                unit.mark_unreadable(rel, format!("not parseable as JSON: {e}"));
                None
            }
        }
    }

    fn load(&self, rel: &str) -> Source {
        let path = self.path(rel);

        let link_meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Source::Absent,
            Err(e) => return Source::Unreadable(format!("cannot be opened: {e}")),
        };

        // A link inside the repository is ordinary — monorepos share one config
        // between workspaces that way. One that leaves it is reported and not
        // followed: its contents are not what someone is about to clone, and
        // resolving it would let a repository make this tool read arbitrary
        // files on the machine running it.
        if link_meta.file_type().is_symlink() {
            match std::fs::canonicalize(&path) {
                Ok(target) if target.starts_with(&self.scan_root) => {}
                Ok(target) => {
                    return Source::Unreadable(format!(
                        "symbolic link leaving the repository, to {} — not followed",
                        display(&target)
                    ));
                }
                Err(e) => return Source::Unreadable(format!("broken symbolic link: {e}")),
            }
        }

        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) => return Source::Unreadable(format!("cannot be opened: {e}")),
        };

        if !meta.is_file() {
            return Source::Unreadable("not a regular file".into());
        }

        if meta.len() > MAX_CONFIG_BYTES {
            return Source::Unreadable(format!(
                "{} bytes, past the {} MiB onopen will read as configuration",
                meta.len(),
                MAX_CONFIG_BYTES / (1024 * 1024)
            ));
        }

        match std::fs::read(&path) {
            Ok(bytes) => match decode(&bytes) {
                Some(text) => Source::Text(text),
                None => Source::Unreadable("not text in any encoding onopen reads".into()),
            },
            Err(e) => Source::Unreadable(format!("cannot be read: {e}")),
        }
    }

    /// Turn an absolute path back into a display path relative to the root.
    pub fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

/// Decode the byte order marks real editors emit.
///
/// VS Code reads a `settings.json` that opens with a UTF-8 BOM without
/// complaint, and `serde_json` refuses it outright; PowerShell's `>` still
/// writes UTF-16. Being stricter than the tool that will actually run the file
/// is one of the ways a scanner reports clean on a repository that is not.
fn decode(bytes: &[u8]) -> Option<String> {
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8(rest.to_vec()).ok(),
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        _ => String::from_utf8(bytes.to_vec()).ok(),
    }
}

fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| unit([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Canonical paths on Windows carry a verbatim `\\?\` prefix. That belongs in
/// an API, not in a line somebody reads.
fn display(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}

pub trait Scanner {
    /// Stable identifier, used in `--json` output and to skip scanners later.
    fn id(&self) -> &'static str;
    fn scan(&self, ctx: &Ctx) -> ScanUnit;
}

pub fn all() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(vscode::VsCode),
        Box::new(editors::Editors),
        Box::new(agents::Agents),
        Box::new(mcp::Mcp),
        Box::new(packages::Packages),
        Box::new(python::Python),
        Box::new(cargo::Cargo),
        Box::new(environments::Environments),
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
