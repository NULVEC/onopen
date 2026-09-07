# Red-team audit 0.5.0

This audit records the verification pass after 0.5.0. The priority is silent
false negatives: a malformed or unusual repository must not become a clean
report by accident.

## Fixed in this pass

- Split indexes: `link` extensions are composed with `sharedindex.<hash>`,
  including deleted, replaced, and added entries.
- Sparse indexes: directory entries ending in `/` are accepted as tracked
  directories and restored into discovery.
- Index boundary: `.git/index` symlinks and gitdir indirections are checked
  before reading; targets outside the scan root are incomplete, not trusted.
- Discovery depth: the filesystem walker and index restoration now use the
  same documented `--depth` boundary.
- npm lifecycle: `preprepare` and `postprepare` are immediate install hooks.
- Additional surfaces: Bun preload, npm Node startup options and script shell,
  `gems.rb`, nox, `usercustomize.py`, executable `.pth` imports, Windsurf,
  Continue, Aider, and Zed task/debug configuration.

## Verification

The repository contains hostile and clean fixtures in `tests/v03.rs`. The pure
index parser is fuzzable through `fuzz/fuzz_targets/gitindex.rs` and never
executes or opens a network connection.

Recommended checks:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo fuzz run gitindex -- -max_total_time=60
```

## Deliberate limits

The parser refuses indexes larger than 64 MiB. This is a resource bound, not a
claim that Git cannot create a larger index; a scan that cannot safely inspect
one exits incomplete (`2`). The bound should be revisited if large monorepos
become a supported target, preferably with streaming parsing rather than an
unbounded allocation.

The `ignore` crate remains pinned to `=0.4.23` because the declared MSRV is
Rust 1.85. Updating it requires either raising MSRV or confirming that the
newer release still builds on 1.85. Dependency advisory checks remain part of
CI.

Hosted CI, ordinary build files, agent prose, and arbitrary Zed tasks remain
out of scope when they do not represent a checked-in editor command surface.
That keeps findings reviewable instead of reporting every build command.
