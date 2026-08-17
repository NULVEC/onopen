//! Minimal JSONC reader.
//!
//! VS Code, devcontainers and most agent tools accept JSON with `//` and `/* */`
//! comments and trailing commas. `serde_json` rejects both, and an attacker who
//! knows a scanner uses a strict parser can hide a payload behind a comment that
//! makes the file unparseable. So we normalise first and parse after.

/// Strip comments and trailing commas so `serde_json` can read the result.
///
/// Comment bytes are replaced with spaces rather than removed, which keeps byte
/// offsets stable in case we ever want to report a position.
pub fn strip(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());

    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];

        if in_string {
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'"' => {
                in_string = true;
                out.push(b);
                i += 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out.push(b' ');
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                out.push(b' ');
                out.push(b' ');
                i += 2;
                while i < bytes.len() {
                    if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                        out.push(b' ');
                        out.push(b' ');
                        i += 2;
                        break;
                    }
                    // Preserve newlines so line numbers survive.
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }

    // `out` only ever copies whole bytes from valid UTF-8 or ASCII spaces, so it
    // is still valid UTF-8.
    let without_comments = String::from_utf8(out).unwrap_or_else(|_| input.to_string());
    strip_trailing_commas(&without_comments)
}

fn strip_trailing_commas(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());

    let mut in_string = false;
    let mut escaped = false;

    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }

        if b == b'"' {
            in_string = true;
            out.push(b);
            continue;
        }

        if b == b',' {
            // Look ahead: a comma followed only by whitespace and then a closing
            // brace or bracket is a trailing comma.
            let next = bytes[i + 1..]
                .iter()
                .find(|c| !c.is_ascii_whitespace())
                .copied();
            if matches!(next, Some(b'}') | Some(b']')) {
                out.push(b' ');
                continue;
            }
        }

        out.push(b);
    }

    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

/// Parse a JSONC string into a `serde_json::Value`.
pub fn parse(input: &str) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(&strip(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_line_comments() {
        let v = parse("{\n  // a comment\n  \"a\": 1\n}").unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn strips_block_comments() {
        let v = parse("{ /* hi */ \"a\": 1 }").unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn strips_trailing_commas() {
        let v = parse("{ \"a\": [1, 2, ], }").unwrap();
        assert_eq!(v["a"][1], 2);
    }

    #[test]
    fn leaves_comment_markers_inside_strings_alone() {
        let v = parse(r#"{ "cmd": "curl https://x.test // not a comment" }"#).unwrap();
        assert_eq!(v["cmd"], "curl https://x.test // not a comment");
    }

    #[test]
    fn handles_escaped_quotes_in_strings() {
        let v = parse(r#"{ "cmd": "say \"hi\" /* nope */" }"#).unwrap();
        assert_eq!(v["cmd"], r#"say "hi" /* nope */"#);
    }

    #[test]
    fn keeps_commas_that_are_not_trailing() {
        let v = parse(r#"{ "a": 1, "b": 2 }"#).unwrap();
        assert_eq!(v["b"], 2);
    }
}
