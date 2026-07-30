# Security policy

## Supported versions

Only the latest release on the default branch (`main`) receives standard re-pins,
permission fixes, and automation updates. Older tags remain readable for pinning
but are not actively maintained.

## Reporting a vulnerability

This repository is a Markdown guidance pack. Reportable issues still include:

- Unsafe or actively harmful security guidance
- Accidental real credentials, private keys, tokens, or personal data in history or tree
- Broken install/release automation that could mislead maintainers into shipping secrets
- Supply-chain issues in GitHub Actions pins used by this repository
- Documentation defects that cause a dangerous false sense of security when followed literally

**Do not** open a public issue with live credentials, customer data, or a private
exploit against a third party. Revoke or rotate first when a real secret is involved,
then report.

Preferred channel: open a **private** security advisory on the GitHub repository
(Security => Advisories => New draft advisory), or contact the maintainer through
the GitHub profile listed on the repository if advisories are unavailable.

### Expectations

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| Initial triage | within 14 days |
| Fix or public mitigation note on supported branch | as soon as practical; content-only fixes often ship as a patch release |

We may ask for a short delay before public discussion when a report affects
downstream consumers who copied guidance verbatim.

## Deliberately vulnerable examples

Skills contain `Vulnerable:` / fixed pairs for teaching. Those blocks must use
**synthetic** values only (`example.invalid`, `REDACTED`, obviously fake keys).
Do not copy a labelled vulnerable block into a real project.

Gitleaks runs in CI with a narrow allowlist. New secret-shaped literals that are
not clearly didactic will fail the build.

## What this project is not

Installing these skills does not add a scanner, WAF, or runtime control plane.
Pair the guidance with SAST, SCA, secret scanning, and normal review. See
[docs/ADOPTION.md](docs/ADOPTION.md) and [README.md](README.md#limitations).
