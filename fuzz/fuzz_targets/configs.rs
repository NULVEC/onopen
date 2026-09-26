#![no_main]

//! Every text parser a repository's config reaches, on the same input: the
//! JSONC reader, and YAML and XML behind their depth and alias limits. None of
//! them may panic, overflow the stack or run away with memory — an abort
//! prints no report at all.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let _ = onopen::jsonc::parse(text);
    let _ = onopen::safeparse::yaml(text);
    let _ = onopen::safeparse::xml(text);
    let _ = onopen::suppress::Suppressions::parse(text);
});
