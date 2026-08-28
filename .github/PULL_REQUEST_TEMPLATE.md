## What this changes

<!-- One or two sentences. What was wrong, and what is different now. -->

## For a new detection

Detections land fixture first, so the test can fail before it passes:

- [ ] A hostile fixture under `tests/fixtures/trapped/`, or built at run time
      if it cannot be committed — a `.git` directory or a symbolic link cannot.
- [ ] Its ordinary counterpart under `tests/fixtures/clean/`. The clean fixture
      must stay completely clean: a rule that fires on a layout millions of
      repositories have is a rule that teaches people to skip the output.
- [ ] A test asserting the rule id **and** the severity.
- [ ] The test observed failing before the rule was implemented.
- [ ] A line in the README's scanner table.

## Severity

<!-- Delete the ones that do not apply, and say why in one line. -->

- `immediate` — runs on open, on session start, or on install, with no further
  action from the reader.
- `deferred` — runs only after a deliberate act: installing, debugging,
  committing, building the container.
- `note` — does not execute on its own, but widens the surface or removes a
  prompt that would have caught something.

## Checks

- [ ] `cargo test`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo fmt --check`
