# Contributing

Onopen reports execution paths, not suspicious-looking strings. A new rule
needs a precise trigger, an honest severity, a hostile fixture and an ordinary
counterpart that remains clean.

Before opening a pull request, run:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --doc
cargo run --release -- . --explain
```

Use the shared `Ctx` read/parse helpers for every candidate configuration.
Never use a best-effort read that turns malformed or inaccessible input into
absence. Never execute a fixture or make a network request from a scanner.

Rule IDs and JSON fields are public API. Prefer adding a rule over silently
changing the meaning of an existing one. If a detection cannot distinguish a
normal project from the proposed execution path, document it as a known limit
instead of shipping a noisy heuristic.
