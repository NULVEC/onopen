//! Repositories that attack the person reading the report, not the scanner.
//!
//! Every string onopen prints about a finding was written by the repository's
//! author. These tests hold the rule that such text reaches the terminal as
//! something to read — `\x1b`, `\u{202e}` — and never as something the terminal
//! or the eye will interpret: no escape sequence rewrites a line or the
//! clipboard, and no bidirectional override reorders a command.
//!
//! JSON is data and keeps the exact bytes (serde escapes the control
//! characters); SARIF escapes the message a reviewer reads and percent-encodes
//! the `uri`, which still decodes to the exact path of the file.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// OSC 52 (write the clipboard), an erase-line plus carriage return to paint
/// over the finding (the carriage return is already flattened to a space, as
/// all whitespace in a command is), an OSC 8 hyperlink, a single-byte C1 CSI, a right-to-left
/// override and a zero-width space. The visible command stays dull on purpose:
/// see the note on `FOLDER_OPEN_TASK` in `hostile.rs` about antivirus.
const HOSTILE_COMMAND: &str = "node ./setup.js\u{1b}]52;c;aGk=\u{7}\u{1b}[2K\rnpm test\u{1b}]8;;https://example.invalid\u{1b}\\x\u{1b}]8;;\u{1b}\\\u{9b}31m \u{202e}sj.pmet\u{202c} a\u{200b}b";

/// What the escaped command has to contain, so a reader can see each trick.
const EXPECTED_ESCAPES: &[&str] = &[
    r"\x1b]52;c;aGk=\x07",
    r"\x1b[2K npm test",
    r"\x1b]8;;https://example.invalid\x1b\x",
    r"\u{9b}31m",
    r"\u{202e}sj.pmet\u{202c}",
    r"a\u{200b}b",
];

/// Characters that must never appear raw in text meant for a terminal.
fn has_raw_hostile_char(s: &str) -> Option<char> {
    s.chars().find(|&c| {
        (c.is_control() && c != '\n')
            || matches!(
                c,
                '\u{061C}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{FEFF}'
            )
    })
}

fn repo(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onopen-hostile-output-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_task(project: &Path, command: &str) {
    fs::create_dir_all(project.join(".vscode")).unwrap();
    let tasks = serde_json::json!({
        "version": "2.0.0",
        "tasks": [{
            "label": "setup",
            "type": "shell",
            "command": command,
            "runOptions": { "runOn": "folderOpen" }
        }]
    });
    fs::write(project.join(".vscode/tasks.json"), tasks.to_string()).unwrap();
}

fn onopen(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_onopen"))
        .arg(dir)
        .args(args)
        .env_remove("NO_COLOR")
        .output()
        .expect("onopen runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("output is UTF-8")
}

#[test]
fn escape_sequences_in_a_command_are_shown_not_interpreted() {
    let dir = repo("command");
    write_task(&dir, HOSTILE_COMMAND);

    for args in [&[][..], &["--explain"][..], &["--show-suppressed"][..]] {
        let output = onopen(&dir, args);
        assert_eq!(output.status.code(), Some(1), "the finding still fails");
        let text = stdout(&output);
        if let Some(c) = has_raw_hostile_char(&text) {
            panic!("raw {c:?} reached the terminal:\n{text}");
        }
        for escape in EXPECTED_ESCAPES {
            assert!(text.contains(escape), "missing {escape:?} in:\n{text}");
        }
    }
}

#[test]
fn a_silenced_hostile_command_is_escaped_in_the_suppressed_list() {
    let dir = repo("suppressed");
    write_task(&dir, HOSTILE_COMMAND);
    fs::write(dir.join(".onopenignore"), "* .vscode/tasks.json\n").unwrap();

    let output = onopen(&dir, &["--show-suppressed"]);
    let text = stdout(&output);
    assert!(text.contains("silenced:"), "{text}");
    if let Some(c) = has_raw_hostile_char(&text) {
        panic!("raw {c:?} reached the terminal:\n{text}");
    }
    assert!(text.contains(r"\u{202e}sj.pmet"), "{text}");
}

#[test]
fn bidi_and_zero_width_characters_in_a_path_are_named() {
    let dir = repo("path");
    // Both are legal in file names on every platform CI runs on.
    let project = dir.join("pkg\u{202e}gpj.\u{200b}x");
    write_task(&project, "node ./setup.js");

    let text = stdout(&onopen(&dir, &[]));
    if let Some(c) = has_raw_hostile_char(&text) {
        panic!("raw {c:?} reached the terminal:\n{text}");
    }
    assert!(text.contains(r"pkg\u{202e}gpj.\u{200b}x/"), "{text}");
}

#[cfg(unix)]
#[test]
fn an_escape_sequence_in_a_path_is_shown_not_interpreted() {
    let dir = repo("unix-path");
    let project = dir.join("pkg\u{1b}[2K\rclean");
    write_task(&project, "node ./setup.js");

    let text = stdout(&onopen(&dir, &[]));
    if let Some(c) = has_raw_hostile_char(&text) {
        panic!("raw {c:?} reached the terminal:\n{text}");
    }
    assert!(
        text.contains(r"pkg\x1b[2K\rclean/.vscode/tasks.json"),
        "{text}"
    );
}

#[test]
fn an_ignore_file_error_does_not_carry_escapes_to_the_terminal() {
    let dir = repo("ignore-error");
    write_task(&dir, "node ./setup.js");
    fs::write(dir.join(".onopenignore"), "* {\u{1b}]52;c;aGk=\u{7}\n").unwrap();

    let output = onopen(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    let err = String::from_utf8(output.stderr).unwrap();
    if let Some(c) = has_raw_hostile_char(&err) {
        panic!("raw {c:?} reached the terminal:\n{err}");
    }
    assert!(err.contains(r"\x1b]52;c;aGk=\x07"), "{err}");
}

#[test]
fn json_keeps_the_exact_command_with_controls_escaped_by_serde() {
    let dir = repo("json");
    write_task(&dir, HOSTILE_COMMAND);

    let output = onopen(&dir, &["--json"]);
    let raw = stdout(&output);
    // JSON only requires C0 to be escaped, and serde does exactly that. DEL,
    // C1 and bidirectional controls travel as UTF-8: the output is data, and a
    // consumer that shows it to a person escapes it for its own medium.
    assert!(
        !raw.chars().any(|c| (c as u32) < 0x20 && c != '\n'),
        "JSON text must carry C0 control characters only as \\u escapes"
    );
    let report: Value = serde_json::from_str(&raw).unwrap();
    let command = report["findings"][0]["command"].as_str().unwrap();
    // The finding records the command as the file has it (whitespace collapsed
    // to one line, as for every finding), not a display rendering of it.
    assert!(command.contains("\u{1b}]52;c;aGk=\u{7}"));
    assert!(command.contains('\u{202e}'));
}

#[test]
fn sarif_escapes_the_message_and_encodes_the_uri() {
    let dir = repo("sarif");
    let project = dir.join("pkg\u{202e}x");
    write_task(&project, HOSTILE_COMMAND);

    let output = onopen(&dir, &["--sarif"]);
    let sarif: Value = serde_json::from_str(&stdout(&output)).unwrap();
    let result = &sarif["runs"][0]["results"][0];
    let message = result["message"]["text"].as_str().unwrap();
    if let Some(c) = has_raw_hostile_char(message) {
        panic!("raw {c:?} in the SARIF message: {message:?}");
    }
    assert!(message.contains(r"\x1b]52;c;aGk=\x07"), "{message}");
    let uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .unwrap();
    // The override arrives as bytes a reviewer can see, not as a reordering,
    // and decoding gives back the name on disk.
    assert_eq!(uri, "pkg%E2%80%AEx/.vscode/tasks.json");
}
