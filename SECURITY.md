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

Terminal escape sequences or bidirectional text that reach a reader
uninterpreted, a configuration file small enough to read that exhausts memory
or the stack, and any network access or write outside stdout and stderr are in
scope as well. `docs/RED-TEAM-1.0.0.md` lists what was tested for 1.0 and the
limits that are deliberate.

## Supported versions

| Version | Security fixes |
|---|---|
| latest `1.x` | yes |
| older `1.x` | upgrade to the latest `1.x`; it never breaks the contract |
| `0.x` | no |

Security fixes ship as a `1.x` patch or minor release. Within 1.x they keep
the contract in `docs/CONTRACT.md`: exit codes, the `--json` schema and the
SARIF shape do not change in a way that breaks a consumer. A fix may still
make onopen report something it used to miss, or exit `2` where it used to
exit `0` on a file it now refuses to read. Reporting clean where it should not
is the one behavior a security fix is allowed to change, and it is always
called out in the changelog.

## Verifying a release

Every release archive is listed in `SHA256SUMS`, carries a Sigstore build
provenance attestation, and ships with a CycloneDX SBOM that is attested too:

```sh
gh attestation verify onopen-<version>-<target>.tar.gz --repo NULVEC/onopen
```

The GitHub Action performs both checks before it runs the binary.
