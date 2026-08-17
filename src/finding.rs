//! The result vocabulary: what a scanner reports and how loudly.

use serde::Serialize;
use std::fmt;

/// How close a finding is to "this executes without you doing anything".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational: worth knowing, does not execute on its own.
    Note,
    /// Runs, but only after a deliberate action (installing, debugging, committing).
    Deferred,
    /// Runs on open, on session start, or on install. This is the one that matters.
    Immediate,
}

impl Severity {
    pub fn marker(self) -> &'static str {
        match self {
            Severity::Immediate => "!",
            Severity::Deferred => "~",
            Severity::Note => "·",
        }
    }

    pub fn ansi(self) -> &'static str {
        match self {
            Severity::Immediate => "\x1b[31m", // red
            Severity::Deferred => "\x1b[33m",  // yellow
            Severity::Note => "\x1b[90m",      // grey
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Immediate => "immediate",
            Severity::Deferred => "deferred",
            Severity::Note => "note",
        };
        f.write_str(s)
    }
}

/// One execution path found in one file.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable rule id, e.g. `vscode/task-run-on-folder-open`.
    pub rule: &'static str,
    /// Path relative to the scan root, always with `/` separators.
    pub file: String,
    /// What causes it to run, e.g. `runOn: folderOpen` or `preinstall`.
    pub trigger: String,
    /// The command that would run, truncated for display.
    pub command: String,
    pub severity: Severity,
    /// One line on why this is an execution path.
    pub note: &'static str,
}

impl Finding {
    pub fn new(
        rule: &'static str,
        file: impl Into<String>,
        trigger: impl Into<String>,
        command: impl Into<String>,
        severity: Severity,
        note: &'static str,
    ) -> Self {
        Self {
            rule,
            file: file.into(),
            trigger: trigger.into(),
            command: truncate(&command.into(), 120),
            severity,
            note,
        }
    }
}

/// What one scanner saw: the files it actually read, and what it found in them.
#[derive(Debug, Default)]
pub struct ScanUnit {
    pub findings: Vec<Finding>,
    /// Files that were parsed and came back with no execution path. Reported so
    /// the output distinguishes "clean" from "never looked".
    pub cleared: Vec<String>,
}

impl ScanUnit {
    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn clear(&mut self, path: impl Into<String>) {
        self.cleared.push(path.into());
    }

    pub fn merge(&mut self, other: ScanUnit) {
        self.findings.extend(other.findings);
        self.cleared.extend(other.cleared);
    }
}

/// Collapse whitespace and cut long commands so one finding stays one line.
pub fn truncate(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let head: String = flat.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}
