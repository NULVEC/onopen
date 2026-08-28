//! Output rendering: a human view built for skimming, and JSON for machines.

use crate::finding::{Finding, ScanUnit, Severity, Unreadable};
use serde::Serialize;
use std::io::IsTerminal;

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[90m";
const BOLD: &str = "\x1b[1m";
/// Unreadable rows get their own colour: they are neither a finding nor clean.
const UNREAD: &str = "\x1b[35m";

#[derive(Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub root: String,
    pub findings: Vec<Finding>,
    pub suppressed: Vec<Finding>,
    /// Files that exist and could not be read. Carried in every output format,
    /// because a report that hides how much of the repository it failed to
    /// read is a report that overstates what it knows.
    pub unreadable: Vec<Unreadable>,
    /// Ignore-file lines that silenced nothing this run.
    pub stale_ignore_lines: Vec<usize>,
    pub summary: Summary,
}

#[derive(Serialize, Default)]
pub struct Summary {
    pub immediate: usize,
    pub deferred: usize,
    pub note: usize,
    pub files_cleared: usize,
    /// Reported even when nothing else is, so a repository cannot be made to
    /// look clean by an ignore file without saying so.
    pub suppressed: usize,
    /// Same promise for files the scan could not read at all.
    pub unreadable: usize,
}

impl Report {
    pub fn build(root: String, mut unit: ScanUnit) -> Self {
        // Loudest first; within a severity keep file order stable so repeated
        // runs on the same tree produce identical output.
        unit.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
        });

        unit.unreadable.sort_by(|a, b| a.file.cmp(&b.file));

        let mut summary = Summary {
            files_cleared: unit.cleared.len(),
            suppressed: unit.suppressed.len(),
            unreadable: unit.unreadable.len(),
            ..Default::default()
        };
        for f in &unit.findings {
            match f.severity {
                Severity::Immediate => summary.immediate += 1,
                Severity::Deferred => summary.deferred += 1,
                Severity::Note => summary.note += 1,
            }
        }

        Self {
            tool: "onopen",
            version: env!("CARGO_PKG_VERSION"),
            root,
            findings: unit.findings,
            suppressed: unit.suppressed,
            unreadable: unit.unreadable,
            stale_ignore_lines: unit.stale_ignore_lines,
            summary,
        }
    }

    /// Exit non-zero only for things that run on their own.
    pub fn should_fail(&self) -> bool {
        self.summary.immediate > 0
    }

    /// Whether part of what the scan was asked to read came back unreadable.
    ///
    /// The answer to "what runs when I open this" is then a partial one, and a
    /// partial answer must not be able to pass for a clean bill of health.
    pub fn is_incomplete(&self) -> bool {
        self.summary.unreadable > 0
    }
}

pub fn render_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

pub struct HumanOptions {
    pub explain: bool,
    pub quiet: bool,
    pub cleared: Vec<String>,
    pub show_suppressed: bool,
}

pub fn render_human(report: &Report, opts: &HumanOptions) -> String {
    let color = use_color();
    let c = |code: &'static str| -> &'static str { if color { code } else { "" } };

    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!(
        "  {}onopen{}  {}{}{}\n\n",
        c(BOLD),
        c(RESET),
        c(DIM),
        report.root,
        c(RESET)
    ));

    if report.findings.is_empty()
        && report.unreadable.is_empty()
        && (opts.quiet || opts.cleared.is_empty())
    {
        out.push_str("  nothing executes on open.\n");
        // An ignore file must never be able to turn a repository clean in
        // silence: whatever it hid gets said here too.
        if report.summary.suppressed > 0 {
            out.push_str(&suppressed_note(report, &c));
        }
        out.push_str(&stale_note(report, &c));
        out.push('\n');
        if opts.show_suppressed {
            out.push_str(&suppressed_list(report, &c));
        }
        return out;
    }

    // Align the three columns against the widest entry so the eye can scan
    // straight down the trigger column.
    let file_w = report
        .findings
        .iter()
        .map(|f| f.file.chars().count())
        .chain(
            report
                .unreadable
                .iter()
                .map(|entry| entry.file.chars().count()),
        )
        .chain(
            opts.cleared
                .iter()
                .filter(|_| !opts.quiet)
                .map(|p| p.chars().count()),
        )
        .max()
        .unwrap_or(0)
        .clamp(0, 38);
    let trig_w = report
        .findings
        .iter()
        .map(|f| f.trigger.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(0, 34);

    for f in &report.findings {
        out.push_str(&format!(
            "{}{}{} {:<fw$}  {:<tw$}  {}{}{}\n",
            c(f.severity.ansi()),
            f.severity.marker(),
            c(RESET),
            fit(&f.file, file_w),
            fit(&f.trigger, trig_w),
            c(DIM),
            f.command,
            c(RESET),
            fw = file_w,
            tw = trig_w,
        ));
        if opts.explain {
            out.push_str(&format!(
                "  {}{}  {}{}\n",
                c(DIM),
                " ".repeat(file_w.min(20)),
                f.note,
                c(RESET)
            ));
        }
    }

    for entry in &report.unreadable {
        out.push_str(&format!(
            "{}?{} {:<fw$}  {}{}{}\n",
            c(UNREAD),
            c(RESET),
            fit(&entry.file, file_w),
            c(UNREAD),
            entry.reason,
            c(RESET),
            fw = file_w
        ));
    }

    if !opts.quiet {
        for path in &opts.cleared {
            out.push_str(&format!(
                "{}  {:<fw$}  clean{}\n",
                c(DIM),
                fit(path, file_w),
                c(RESET),
                fw = file_w
            ));
        }
    }

    out.push('\n');
    out.push_str(&summary_line(report, &c));
    if report.summary.unreadable > 0 {
        out.push_str(&incomplete_note(report, &c));
    }
    if report.summary.suppressed > 0 {
        out.push_str(&suppressed_note(report, &c));
    }
    out.push_str(&stale_note(report, &c));
    out.push('\n');
    if opts.show_suppressed {
        out.push_str(&suppressed_list(report, &c));
    }
    out
}

/// One line naming what the scan could not read.
///
/// Printed for the same reason the suppression note is printed: the summary
/// above it counts execution paths, and a reader who sees a low number needs to
/// know in the same breath how much of the repository never got read.
fn incomplete_note(report: &Report, c: &impl Fn(&'static str) -> &'static str) -> String {
    let n = report.summary.unreadable;
    let (noun, pronoun) = if n == 1 {
        ("file", "it")
    } else {
        ("files", "them")
    };
    format!(
        "  {}{n} {noun} could not be read — onopen cannot tell you what is in {pronoun}{}\n",
        c(BOLD),
        c(RESET)
    )
}

/// Names the ignore-file lines that silenced nothing.
///
/// A dead ignore line reads as protection to whoever finds it in the file, and
/// is none: the rule id was renamed, or the path moved. Saying so is the same
/// promise the rest of this file keeps — an ignore file may hide a finding, but
/// never quietly stop doing its job.
fn stale_note(report: &Report, c: &impl Fn(&'static str) -> &'static str) -> String {
    if report.stale_ignore_lines.is_empty() {
        return String::new();
    }
    let lines: Vec<String> = report
        .stale_ignore_lines
        .iter()
        .map(|n| n.to_string())
        .collect();
    let (noun, verb) = if lines.len() == 1 {
        ("line", "silenced")
    } else {
        ("lines", "silenced")
    };
    format!(
        "  {}ignore file {noun} {} {verb} nothing — the rule id or the path may have moved{}\n",
        c(DIM),
        lines.join(", "),
        c(RESET)
    )
}

/// One line naming how much an ignore file silenced. Printed whenever
/// anything was silenced, including on an otherwise clean report.
fn suppressed_note(report: &Report, c: &impl Fn(&'static str) -> &'static str) -> String {
    let n = report.summary.suppressed;
    let noun = if n == 1 { "finding" } else { "findings" };
    format!(
        "  {}{n} {noun} silenced by an ignore file — run with --show-suppressed to read them{}\n",
        c(DIM),
        c(RESET)
    )
}

fn suppressed_list(report: &Report, c: &impl Fn(&'static str) -> &'static str) -> String {
    if report.suppressed.is_empty() {
        return String::new();
    }
    let mut out = format!("  {}silenced:{}\n", c(DIM), c(RESET));
    for f in &report.suppressed {
        out.push_str(&format!(
            "  {}- {}  {}  {}{}\n",
            c(DIM),
            f.file,
            f.trigger,
            f.command,
            c(RESET)
        ));
    }
    out.push('\n');
    out
}

fn summary_line(report: &Report, c: &impl Fn(&'static str) -> &'static str) -> String {
    let s = &report.summary;

    if s.immediate == 0 {
        let tail = if s.deferred + s.note > 0 {
            format!(" ({} deferred, {} to note)", s.deferred, s.note)
        } else {
            String::new()
        };
        return format!(
            "  {}no execution paths before you type a line{}{}\n",
            c(DIM),
            tail,
            c(RESET)
        );
    }

    let noun = if s.immediate == 1 {
        "execution path"
    } else {
        "execution paths"
    };
    let tail = if s.deferred + s.note > 0 {
        format!(
            "{} · {} deferred, {} to note{}",
            c(DIM),
            s.deferred,
            s.note,
            c(RESET)
        )
    } else {
        String::new()
    };

    format!(
        "  {}{}{} {} before you type a line{}\n",
        c(BOLD),
        s.immediate,
        c(RESET),
        noun,
        tail
    )
}

/// Cut a cell to the column width so the columns stay square. The widths are
/// derived from the data and only bite on unusually long labels.
fn fit(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    let head: String = s.chars().take(width.saturating_sub(1)).collect();
    format!("{head}…")
}

/// Colour when we are talking to a terminal and NO_COLOR is unset.
fn use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}
