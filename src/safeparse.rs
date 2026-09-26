//! The YAML and XML parsers, with the limits they do not bring themselves.
//!
//! Every config onopen reads is already capped at [`MAX_CONFIG_BYTES`], and
//! `serde_json` and `toml` refuse deep nesting on their own. Two gaps were
//! left, both small files that cost far more than their size:
//!
//! - **YAML aliases.** `yaml-rust2` resolves `*alias` by copying the anchored
//!   node. Ten anchors of ten aliases each is a few hundred bytes that expand
//!   to ten billion nodes — the "billion laughs" — and the scan runs out of
//!   memory before any finding is reported. The events are counted first, with
//!   every alias weighing what it expands to, and a document past
//!   [`MAX_YAML_NODES`] is refused unread.
//! - **XML nesting.** `roxmltree` recurses once per open element, and on the
//!   1 MiB main-thread stack Windows gives a process about a thousand `<a>`
//!   are enough to overflow it: an abort, not an error, and no report at all.
//!   Depth is measured by a lexical pass before parsing, and a document deeper
//!   than [`MAX_XML_DEPTH`] is refused. DTDs stay disabled (the `roxmltree`
//!   default), so entities cannot hide elements from that pass.
//!
//! Refused files are reported unreadable by the caller, which is what keeps
//! them out of the clean list and the exit code at 2.
//!
//! [`MAX_CONFIG_BYTES`]: crate::scanners::MAX_CONFIG_BYTES

use std::collections::HashMap;
use yaml_rust2::parser::{Event, EventReceiver, Parser};
use yaml_rust2::{Yaml, YamlLoader};

/// Nodes a YAML document may hold once its aliases are expanded. A large
/// real `pnpm-workspace.yaml` or `.pre-commit-config.yaml` holds a few
/// thousand.
pub const MAX_YAML_NODES: u64 = 100_000;

/// Element depth an XML document may reach. IntelliJ's files nest a handful
/// of levels; the limit is far from them and far from the stack.
pub const MAX_XML_DEPTH: usize = 256;

/// Parse YAML, refusing documents whose aliases expand past the budget.
pub fn yaml(source: &str) -> Result<Vec<Yaml>, String> {
    let mut counter = NodeCounter::default();
    Parser::new_from_str(source)
        .load(&mut counter, true)
        .map_err(|e| e.to_string())?;
    if counter.over {
        return Err(format!(
            "aliases expand past {MAX_YAML_NODES} nodes — refused unread (\"billion laughs\")"
        ));
    }
    YamlLoader::load_from_str(source).map_err(|e| e.to_string())
}

/// Parse XML, refusing documents nested deeper than the stack can follow.
pub fn xml(source: &str) -> Result<roxmltree::Document<'_>, String> {
    if let Some(depth) = xml_depth_past(source, MAX_XML_DEPTH) {
        return Err(format!(
            "elements nested past {depth} levels, deeper than the {MAX_XML_DEPTH} onopen parses"
        ));
    }
    roxmltree::Document::parse(source).map_err(|e| e.to_string())
}

/// Counts the nodes a YAML stream would hold once every alias is replaced by
/// a copy of its anchor, without building any of them.
#[derive(Default)]
struct NodeCounter {
    /// Expanded size of every anchored node seen so far.
    anchors: HashMap<usize, u64>,
    /// Open collections: their anchor id and the nodes counted inside so far.
    open: Vec<(usize, u64)>,
    total: u64,
    over: bool,
}

impl NodeCounter {
    fn finish(&mut self, size: u64) {
        match self.open.last_mut() {
            Some((_, inside)) => *inside = inside.saturating_add(size),
            None => self.total = self.total.saturating_add(size),
        }
        let inside = self.open.last().map_or(0, |(_, n)| *n);
        if size > MAX_YAML_NODES || inside > MAX_YAML_NODES || self.total > MAX_YAML_NODES {
            self.over = true;
        }
    }
}

impl EventReceiver for NodeCounter {
    fn on_event(&mut self, ev: Event) {
        if self.over {
            return;
        }
        match ev {
            Event::Scalar(_, _, anchor, _) => {
                if anchor > 0 {
                    self.anchors.insert(anchor, 1);
                }
                self.finish(1);
            }
            Event::Alias(anchor) => {
                let size = self.anchors.get(&anchor).copied().unwrap_or(1);
                self.finish(size);
            }
            Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                self.open.push((anchor, 1));
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some((anchor, size)) = self.open.pop() {
                    if anchor > 0 {
                        self.anchors.insert(anchor, size);
                    }
                    self.finish(size);
                }
            }
            _ => {}
        }
    }
}

/// The element depth a document reaches, if it goes past `limit`.
///
/// Lexical, not a parser: it only has to never say "shallow" about a document
/// `roxmltree` would find deep. Comments, CDATA, processing instructions and
/// declarations are skipped the way the parser skips them; quoted attribute
/// values are skipped so a `>` inside one does not end the tag early.
fn xml_depth_past(text: &str, limit: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;

    let skip_past = |from: usize, end: &[u8]| -> usize {
        bytes[from..]
            .windows(end.len())
            .position(|w| w == end)
            .map_or(bytes.len(), |p| from + p + end.len())
    };

    while let Some(offset) = bytes[i..].iter().position(|&b| b == b'<') {
        i += offset;
        let rest = &bytes[i..];
        if rest.starts_with(b"<!--") {
            i = skip_past(i + 4, b"-->");
        } else if rest.starts_with(b"<![CDATA[") {
            i = skip_past(i + 9, b"]]>");
        } else if rest.starts_with(b"<?") {
            i = skip_past(i + 2, b"?>");
        } else if rest.starts_with(b"<!") {
            i = skip_past(i + 2, b">");
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            i = skip_past(i + 2, b">");
        } else {
            // A start tag: find its `>` outside quotes, and whether it closes
            // itself.
            let mut j = i + 1;
            let mut quote = None;
            let mut self_closing = false;
            while j < bytes.len() {
                let b = bytes[j];
                match quote {
                    Some(q) if b == q => quote = None,
                    Some(_) => {}
                    None if b == b'"' || b == b'\'' => quote = Some(b),
                    None if b == b'>' => {
                        self_closing = bytes[j - 1] == b'/';
                        break;
                    }
                    None => {}
                }
                j += 1;
            }
            if !self_closing {
                depth += 1;
                if depth > limit {
                    return Some(depth);
                }
            }
            i = (j + 1).min(bytes.len());
        }
        if i >= bytes.len() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_yaml_with_anchors_is_parsed() {
        let docs = yaml("base: &b {x: 1}\nrepos:\n  - *b\n  - *b\n").unwrap();
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn a_billion_laughs_is_refused_before_it_is_expanded() {
        let mut s = String::from("a0: &a0 [lol,lol,lol,lol,lol,lol,lol,lol,lol,lol]\n");
        for i in 1..10 {
            let prev = format!("*a{}", i - 1);
            s.push_str(&format!("a{i}: &a{i} [{}]\n", vec![prev; 10].join(",")));
        }
        let err = yaml(&s).unwrap_err();
        assert!(err.contains("billion laughs"), "{err}");
    }

    #[test]
    fn ordinary_xml_is_parsed() {
        let doc = xml(r#"<project version="4"><component name="a>b"/><!-- <x><x> --></project>"#)
            .unwrap();
        assert_eq!(doc.root_element().tag_name().name(), "project");
    }

    #[test]
    fn depth_counts_open_elements_only() {
        let deep = format!("{}{}", "<a>".repeat(300), "</a>".repeat(300));
        assert_eq!(xml_depth_past(&deep, 256), Some(257));
        let wide = "<a></a>".repeat(10_000);
        assert_eq!(xml_depth_past(&wide, 256), None);
        let closed = "<r>".to_string() + &"<a/>".repeat(1000) + "</r>";
        assert_eq!(xml_depth_past(&closed, 256), None);
        let commented = format!(
            "<r><!--{}--><![CDATA[{}]]></r>",
            "<a>".repeat(500),
            "<a>".repeat(500)
        );
        assert_eq!(xml_depth_past(&commented, 256), None);
    }
}
