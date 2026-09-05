//! Reading `.git/index`, so `.gitignore` stops hiding what is in the clone.
//!
//! `.gitignore` is not a filter on the repository's contents. Git applies it to
//! files it does not already track, and to nothing else — once a file is in the
//! index, a later pattern covering it changes nothing: it stays committed, and
//! everyone who clones gets it. A walker that treats ignore rules as the truth
//! about what a clone contains can therefore be steered:
//!
//! ```text
//! git add -f packages/api/.vscode/tasks.json
//! echo 'packages/' >> .gitignore
//! git commit -am 'tidy up the workspace'
//! ```
//!
//! The task is in every clone and fires on folder open. The walker never sees
//! the directory, and the scan exits 0 with "nothing executes on open" — the
//! one failure this tool cannot afford.
//!
//! So the index is read directly. Not by running `git`: onopen's promise is
//! that it reads and parses and never executes, and shelling out to a binary
//! resolved from `PATH` inside a repository someone has not read yet would be a
//! strange way to keep it. The format is documented and small.

use std::path::{Path, PathBuf};

/// The index of a repository with a hundred thousand files is a few megabytes.
/// Past this, what is at `.git/index` is not something we should pull into
/// memory on the strength of its name.
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

/// Object names are 20 bytes of SHA-1 or 32 of SHA-256. The index format does
/// not record which, so both are tried and the one that parses wins.
const HASH_LENGTHS: [usize; 2] = [20, 32];

/// What asking a directory for its tracked files came back with.
pub enum Index {
    /// No repository here. Ignore rules are all there is to go on, which is
    /// correct: with no index, nothing is tracked.
    None,
    /// Paths relative to the repository root, `/`-separated, as git stores them.
    Tracked(Vec<String>),
    /// There is a repository and its index could not be read. Neither "clean"
    /// nor "tracked": we do not know what this clone contains.
    Unreadable(String),
}

/// Read the tracked paths of the repository rooted at `root`.
///
/// Only `root` itself is examined. A scan pointed at a subdirectory of a
/// repository gets `None`, which matches the walker: it does not read parent
/// `.gitignore` files either, so there is nothing there to correct.
pub fn read(root: &Path) -> Index {
    let git_dir = match git_dir(root) {
        Ok(Some(dir)) => dir,
        Ok(None) => return Index::None,
        Err(reason) => return Index::Unreadable(reason),
    };

    let index = git_dir.join("index");
    let meta = match std::fs::metadata(&index) {
        Ok(meta) => meta,
        // A repository with no index has nothing staged and nothing tracked —
        // `git init` and no more. That is an answer, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Index::Tracked(Vec::new()),
        Err(e) => return Index::Unreadable(format!("cannot be opened: {e}")),
    };

    if meta.len() > MAX_INDEX_BYTES {
        return Index::Unreadable(format!(
            "{} bytes, past the {} MiB onopen will read as an index",
            meta.len(),
            MAX_INDEX_BYTES / (1024 * 1024)
        ));
    }

    let bytes = match std::fs::read(&index) {
        Ok(bytes) => bytes,
        Err(e) => return Index::Unreadable(format!("cannot be read: {e}")),
    };

    match parse(&bytes) {
        Ok(paths) => Index::Tracked(paths),
        Err(reason) => Index::Unreadable(reason),
    }
}

/// Where this repository keeps its administrative files.
///
/// Usually `root/.git`. A worktree or a submodule puts a file there instead,
/// holding the path to the real one.
fn git_dir(root: &Path) -> Result<Option<PathBuf>, String> {
    let dot = root.join(".git");

    match std::fs::metadata(&dot) {
        Ok(meta) if meta.is_dir() => return Ok(Some(dot)),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot be opened: {e}")),
    }

    let text =
        std::fs::read_to_string(&dot).map_err(|e| format!("is a file and cannot be read: {e}"))?;
    let target = text
        .lines()
        .find_map(|line| line.strip_prefix("gitdir:"))
        .ok_or_else(|| "is a file with no `gitdir:` line in it".to_string())?
        .trim();
    if target.is_empty() {
        return Err("is a file whose `gitdir:` line names nothing".into());
    }

    let target = Path::new(target);
    Ok(Some(if target.is_absolute() {
        target.to_path_buf()
    } else {
        root.join(target)
    }))
}

/// Parse the entry table of a `DIRC` index.
///
/// Extensions after the entries — the cache tree, the untracked cache, the
/// end-of-index record — are skipped. They are derived data, and the entries
/// are the authoritative list of what the repository tracks.
fn parse(bytes: &[u8]) -> Result<Vec<String>, String> {
    if bytes.len() < 12 {
        return Err(format!(
            "{} bytes, shorter than an index header",
            bytes.len()
        ));
    }
    if &bytes[..4] != b"DIRC" {
        return Err("does not begin with the DIRC signature".into());
    }

    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if !(2..=4).contains(&version) {
        return Err(format!("index version {version} is not one onopen reads"));
    }

    let count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    // The smallest possible entry is the 40-byte stat block, an object name, two
    // flag bytes and a name. Anything claiming more entries than could fit is a
    // header that does not describe this file.
    if count > bytes.len() {
        return Err(format!(
            "header claims {count} entries, more than {} bytes can hold",
            bytes.len()
        ));
    }

    for hash_len in HASH_LENGTHS {
        if let Some(paths) = entries(bytes, version, count, hash_len) {
            return Ok(paths);
        }
    }

    Err(format!(
        "{count} entries do not parse as version {version} with either object-name length"
    ))
}

/// The low twelve bits of the flags hold the name length, or this when the name
/// is too long to fit in them.
const NAME_MASK: u16 = 0x0FFF;

/// Walk the entry table assuming object names of `hash_len` bytes.
///
/// `None` means the assumption was wrong or the table is damaged; the caller
/// cannot tell those apart, and for our purposes it does not need to. Every
/// read is bounds-checked, so a hostile index makes this return `None` rather
/// than panic.
///
/// Two invariants git maintains do the work of telling a misread table from a
/// real one: the flags repeat the length of the name that follows them, and
/// entries are sorted. Read a SHA-256 index as if its object names were twenty
/// bytes and twelve bytes of hash land where the flags belong — which passes a
/// bounds check and almost never passes those two.
fn entries(bytes: &[u8], version: u32, count: usize, hash_len: usize) -> Option<Vec<String>> {
    let mut paths = Vec::with_capacity(count.min(4096));
    let mut previous: Vec<u8> = Vec::new();
    let mut previous_stage = 0u16;
    let mut pos = 12usize;

    for entry in 0..count {
        let start = pos;
        // 40 bytes of stat data, the object name, then the 16-bit flags.
        let flags_at = start.checked_add(40)?.checked_add(hash_len)?;
        let after_flags = flags_at.checked_add(2)?;
        if after_flags > bytes.len() {
            return None;
        }

        let flags = u16::from_be_bytes([bytes[flags_at], bytes[flags_at + 1]]);
        let stage = (flags >> 12) & 0x3;
        let claimed_len = flags & NAME_MASK;
        let mut p = after_flags;
        // The extended bit means a second set of flags follows. Version 2 has
        // no such thing, so seeing it there means we are misreading the table.
        if flags & 0x4000 != 0 {
            if version < 3 {
                return None;
            }
            p = p.checked_add(2)?;
            if p > bytes.len() {
                return None;
            }
        }

        // Version 4 stores each name as "drop N bytes from the end of the
        // previous one, then append this" — the entries are sorted, so
        // neighbours share long prefixes.
        let mut name: Vec<u8> = if version >= 4 {
            let strip = varint(bytes, &mut p)?;
            let keep = previous.len().checked_sub(strip)?;
            previous[..keep].to_vec()
        } else {
            Vec::new()
        };

        let end = bytes.get(p..)?.iter().position(|b| *b == 0)?;
        let suffix = &bytes[p..p + end];
        // Control bytes never appear in a path git stores. Rejecting them is
        // what makes a wrong object-name length fail here instead of yielding
        // plausible-looking rubbish.
        if suffix.iter().any(|b| *b < 0x20) {
            return None;
        }
        name.extend_from_slice(suffix);
        if !usable(&name) {
            return None;
        }

        // The flags repeat the name length, capped at the twelve bits they have
        // to say it in. A disagreement means those two bytes were not the flags.
        if claimed_len != NAME_MASK && usize::from(claimed_len) != name.len() {
            return None;
        }

        // Entries are sorted by name, and a path repeats only across the stages
        // of a merge conflict. Bytes that happen to look like a path do not
        // usually arrive in order.
        if entry > 0 && (name.as_slice(), stage) <= (previous.as_slice(), previous_stage) {
            return None;
        }

        pos = if version >= 4 {
            // No padding: the next entry begins after the terminator.
            p.checked_add(end)?.checked_add(1)?
        } else {
            // The entry is padded with one to eight NUL bytes to a multiple of
            // eight, counting from where the entry began.
            let used = p.checked_add(end)?.checked_add(1)?.checked_sub(start)?;
            start.checked_add(used.next_multiple_of(8))?
        };
        if pos > bytes.len() {
            return None;
        }

        paths.push(String::from_utf8_lossy(&name).into_owned());
        previous = name;
        previous_stage = stage;
    }

    // The file ends with a checksum over everything before it. If there is not
    // even room for that, the table did not end where we think it did.
    if bytes.len().checked_sub(pos)? < hash_len {
        return None;
    }

    Some(paths)
}

/// A path git could have stored, and that we can safely turn back into a
/// location under the scan root.
///
/// Absolute paths, `..` components and backslashes are all things a real index
/// does not contain. A crafted one might, and following it would let a
/// repository point this tool at a directory outside itself.
fn usable(name: &[u8]) -> bool {
    if name.is_empty() || name[0] == b'/' || name.contains(&b'\\') {
        return false;
    }
    // A Windows drive letter: `C:/...`.
    if name.len() >= 2 && name[1] == b':' {
        return false;
    }
    !name
        .split(|b| *b == b'/')
        .any(|part| part == b".." || part.is_empty())
}

/// The variable-width integer version 4 uses for its prefix lengths.
///
/// Each continuation adds one before shifting, so the encoding has no
/// redundant representations — this is git's `decode_varint`, not LEB128.
fn varint(bytes: &[u8], pos: &mut usize) -> Option<usize> {
    let mut byte = *bytes.get(*pos)?;
    *pos += 1;
    let mut value = (byte & 0x7f) as usize;
    // A path length needs a handful of bytes at most; the bound stops a
    // damaged index from walking the whole file one byte at a time.
    for _ in 0..9 {
        if byte & 0x80 == 0 {
            return Some(value);
        }
        value = value.checked_add(1)?;
        byte = *bytes.get(*pos)?;
        *pos += 1;
        value = value
            .checked_mul(128)?
            .checked_add((byte & 0x7f) as usize)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an index the way git writes one, so the parser is tested against
    /// the format rather than against itself.
    struct Builder {
        version: u32,
        hash_len: usize,
        entries: Vec<u8>,
        count: u32,
        previous: String,
    }

    impl Builder {
        fn new(version: u32) -> Self {
            Self {
                version,
                hash_len: 20,
                entries: Vec::new(),
                count: 0,
                previous: String::new(),
            }
        }

        fn sha256(mut self) -> Self {
            self.hash_len = 32;
            self
        }

        fn add(mut self, path: &str) -> Self {
            let start = self.entries.len();
            self.entries.extend_from_slice(&[0u8; 40]);
            self.entries
                .extend(std::iter::repeat_n(0xABu8, self.hash_len));
            let name_len = u16::try_from(path.len()).unwrap_or(0xFFF).min(0xFFF);
            self.entries.extend_from_slice(&name_len.to_be_bytes());

            if self.version >= 4 {
                let shared = self
                    .previous
                    .bytes()
                    .zip(path.bytes())
                    .take_while(|(a, b)| a == b)
                    .count();
                let strip = self.previous.len() - shared;
                self.entries.extend_from_slice(&encode_varint(strip));
                self.entries.extend_from_slice(&path.as_bytes()[shared..]);
                self.entries.push(0);
            } else {
                self.entries.extend_from_slice(path.as_bytes());
                self.entries.push(0);
                let used = self.entries.len() - start;
                self.entries.resize(start + used.next_multiple_of(8), 0);
            }

            self.previous = path.to_string();
            self.count += 1;
            self
        }

        fn build(self) -> Vec<u8> {
            let mut out = Vec::from(*b"DIRC");
            out.extend_from_slice(&self.version.to_be_bytes());
            out.extend_from_slice(&self.count.to_be_bytes());
            out.extend_from_slice(&self.entries);
            // The trailing checksum. Its value is never verified: a wrong one
            // means the file is damaged, and a damaged index is exactly what a
            // repository cannot use to make us look somewhere else.
            out.extend(std::iter::repeat_n(0u8, self.hash_len));
            out
        }
    }

    fn encode_varint(mut value: usize) -> Vec<u8> {
        let mut out = vec![(value & 0x7f) as u8];
        while value >= 128 {
            value = (value >> 7) - 1;
            out.insert(0, (value & 0x7f) as u8 | 0x80);
        }
        out
    }

    #[test]
    fn reads_a_version_two_index() {
        let bytes = Builder::new(2)
            .add("README.md")
            .add("packages/api/.vscode/tasks.json")
            .build();
        assert_eq!(
            parse(&bytes).unwrap(),
            vec!["README.md", "packages/api/.vscode/tasks.json"]
        );
    }

    #[test]
    fn reads_a_version_four_index() {
        // Prefix compression: the second path repeats all but the last segment
        // of the first, so this only parses if the varint is read git's way.
        let bytes = Builder::new(4)
            .add("packages/api/.vscode/launch.json")
            .add("packages/api/.vscode/tasks.json")
            .add("packages/web/package.json")
            .build();
        assert_eq!(
            parse(&bytes).unwrap(),
            vec![
                "packages/api/.vscode/launch.json",
                "packages/api/.vscode/tasks.json",
                "packages/web/package.json",
            ]
        );
    }

    #[test]
    fn reads_a_sha256_index() {
        // Nothing in the header says how long an object name is, so the parser
        // has to work it out. A 32-byte one must not be read as a 20-byte one.
        let bytes = Builder::new(2).sha256().add("Cargo.toml").build();
        assert_eq!(parse(&bytes).unwrap(), vec!["Cargo.toml"]);
    }

    #[test]
    fn an_empty_index_tracks_nothing() {
        assert!(parse(&Builder::new(2).build()).unwrap().is_empty());
    }

    #[test]
    fn a_damaged_index_is_refused_rather_than_read_as_empty() {
        let mut bytes = Builder::new(2).add("package.json").build();
        // Claim one more entry than the file holds. Reporting this as "tracks
        // one file" would be the silent failure the whole module exists to stop.
        bytes[11] = 2;
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn a_file_that_is_not_an_index_is_refused() {
        assert!(parse(b"not an index at all").is_err());
        assert!(parse(b"DIRC").is_err());
    }

    #[test]
    fn a_path_leaving_the_repository_is_refused() {
        // A real index cannot contain this. One handed to us can, and joining
        // it to the scan root would walk out of the repository.
        let bytes = Builder::new(2).add("../../../etc/profile.d").build();
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn varint_round_trips_the_way_git_encodes_it() {
        for value in [0usize, 1, 127, 128, 129, 255, 16511, 16512, 100_000] {
            let encoded = encode_varint(value);
            let mut pos = 0;
            assert_eq!(varint(&encoded, &mut pos), Some(value), "value {value}");
            assert_eq!(pos, encoded.len(), "value {value} left bytes unread");
        }
    }
}
