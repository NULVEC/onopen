//! Silencing findings a team has already looked at.
//!
//! Every scanner that gets adopted needs this. A repository has its own
//! `postinstall` that builds a native module, someone reads it once, decides it
//! is fine, and then needs the tool to stop reporting it — otherwise the first
//! false positive is also the last run, and the scanner comes out of CI.
//!
//! The rule this file exists to enforce is that suppression is never silent.
//! A scanner that can be told to look away without saying so is worse than no
//! scanner, because it reports clean with authority. Suppressed findings are
//! counted, reported, and listable; they are hidden, never forgotten.

use crate::finding::Finding;
use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use std::path::Path;

/// The file read from the scan root unless another path is given.
pub const DEFAULT_IGNORE_FILE: &str = ".onopenignore";

/// Paths reach here already canonicalised, which on Windows means the verbatim
/// `\?\` prefix. That belongs in an API, not in a message someone reads.
fn display(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string()
}

/// One line of the ignore file: a rule to silence, and where to silence it.
#[derive(Debug)]
struct Rule {
    /// Rule id, or `None` for `*` — any rule.
    rule: Option<String>,
    /// Path glob, or `None` for `*` — any file.
    path: Option<GlobMatcher>,
    /// The line it came from, for `--show-suppressed`.
    source_line: usize,
}

impl Rule {
    fn matches(&self, finding: &Finding) -> bool {
        if let Some(rule) = &self.rule {
            if rule != finding.rule {
                return false;
            }
        }
        match &self.path {
            Some(glob) => glob.is_match(&finding.file),
            None => true,
        }
    }
}

#[derive(Debug, Default)]
pub struct Suppressions {
    rules: Vec<Rule>,
}

impl Suppressions {
    /// Read the ignore file if there is one. A missing file is not an error:
    /// most repositories will never need one.
    pub fn load(root: &Path, explicit: Option<&Path>) -> Result<Self> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => root.join(DEFAULT_IGNORE_FILE),
        };

        let shown = display(&path);

        if !path.exists() {
            // An explicitly requested file that is not there is a mistake worth
            // reporting; the default one simply does not exist yet.
            if explicit.is_some() {
                anyhow::bail!("ignore file not found: {shown}");
            }
            return Ok(Self::default());
        }

        let text =
            std::fs::read_to_string(&path).with_context(|| format!("cannot read {shown}"))?;
        Self::parse(&text).with_context(|| format!("in {shown}"))
    }

    /// ```text
    /// # comment
    /// <rule-id|*>  <path-glob|*>   # why it is silenced
    /// ```
    pub fn parse(text: &str) -> Result<Self> {
        let mut rules = Vec::new();

        for (index, raw) in text.lines().enumerate() {
            let line_number = index + 1;
            // A `#` only starts a comment at the beginning of a field, so a
            // glob is free to contain one.
            let line = match raw.split_once(" #") {
                Some((before, _)) => before,
                None => raw.strip_prefix('#').map(|_| "").unwrap_or(raw),
            }
            .trim();

            if line.is_empty() {
                continue;
            }

            let mut fields = line.split_whitespace();
            let rule_field = fields.next().unwrap_or("*");
            let path_field = fields.next().unwrap_or("*");

            if fields.next().is_some() {
                anyhow::bail!(
                    "line {line_number}: expected `<rule> <path>`, found extra fields. \
                     Put the reason after ` #`."
                );
            }

            let path = if path_field == "*" {
                None
            } else {
                Some(
                    Glob::new(path_field)
                        .with_context(|| format!("line {line_number}: bad path pattern"))?
                        .compile_matcher(),
                )
            };

            let rule = if rule_field == "*" {
                None
            } else {
                Some(rule_field.to_string())
            };

            if rule.is_none() && path.is_none() {
                anyhow::bail!(
                    "line {line_number}: `* *` would silence every finding, which is the \
                     same as not running the scanner"
                );
            }

            rules.push(Rule {
                rule,
                path,
                source_line: line_number,
            });
        }

        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The ignore-file line that silences this finding, if any.
    pub fn matching_line(&self, finding: &Finding) -> Option<usize> {
        self.rules
            .iter()
            .find(|r| r.matches(finding))
            .map(|r| r.source_line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn finding(rule: &'static str, file: &str) -> Finding {
        Finding::new(
            rule,
            file,
            "trigger",
            "command",
            Severity::Immediate,
            "note",
        )
    }

    #[test]
    fn silences_one_rule_in_one_file() {
        let s = Suppressions::parse("npm/install-lifecycle-script  packages/legacy/package.json")
            .unwrap();
        assert!(
            s.matching_line(&finding(
                "npm/install-lifecycle-script",
                "packages/legacy/package.json"
            ))
            .is_some()
        );
        // Same rule, different file: still reported.
        assert!(
            s.matching_line(&finding("npm/install-lifecycle-script", "package.json"))
                .is_none()
        );
        // Same file, different rule: still reported.
        assert!(
            s.matching_line(&finding(
                "npm/other-lifecycle-script",
                "packages/legacy/package.json"
            ))
            .is_none()
        );
    }

    #[test]
    fn a_star_widens_one_axis_at_a_time() {
        let by_rule = Suppressions::parse("agent/command-hook  *").unwrap();
        assert!(
            by_rule
                .matching_line(&finding(
                    "agent/command-hook",
                    "anywhere/.claude/settings.json"
                ))
                .is_some()
        );

        let by_path = Suppressions::parse("*  vendor/**").unwrap();
        assert!(
            by_path
                .matching_line(&finding(
                    "npm/install-lifecycle-script",
                    "vendor/x/package.json"
                ))
                .is_some()
        );
        assert!(
            by_path
                .matching_line(&finding("npm/install-lifecycle-script", "src/package.json"))
                .is_none()
        );
    }

    #[test]
    fn refuses_to_silence_everything() {
        let err = Suppressions::parse("*  *").unwrap_err();
        assert!(err.to_string().contains("every finding"));
    }

    #[test]
    fn keeps_comments_and_blank_lines_out_of_the_way() {
        let s = Suppressions::parse(
            "# our own build step\n\
             \n\
             npm/install-lifecycle-script  package.json  # reviewed 2026-08, builds a native module\n",
        )
        .unwrap();
        assert_eq!(
            s.matching_line(&finding("npm/install-lifecycle-script", "package.json")),
            Some(3)
        );
    }

    #[test]
    fn a_bad_pattern_is_an_error_rather_than_a_silent_no_op() {
        let err = Suppressions::parse("*  [unclosed").unwrap_err();
        assert!(err.to_string().contains("line 1"));
    }
}
