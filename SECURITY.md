# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do
not open a public issue for a bypass that could make Onopen report a hostile
repository as clean.

Include the smallest repository or configuration file that reproduces the
problem, the Onopen version, operating system, output format and exact command.
Do not include real credentials, tokens or private repository contents.

We treat false-clean results, unsafe filesystem traversal, unintended command
execution, and release-integrity failures as security issues. Onopen is a
static scanner: it must never execute repository content or follow a file
symlink outside the scan root.

Supported security fixes target the latest released `0.x` version. Until the
project reaches `1.0`, security-relevant behavior may still tighten between
minor releases and will be called out in the changelog.
