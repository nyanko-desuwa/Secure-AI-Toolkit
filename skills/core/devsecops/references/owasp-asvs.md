# OWASP, ASVS, and CWE Mapping

Verified 2026-07-28. This skill cites OWASP Top 10 2025 and ASVS 5.0.0. The 2025 Top 10 is not a
renumbering of 2021.

## OWASP Top 10 2025

Source: <https://owasp.org/Top10/2025/>

### A03:2025 — Software Supply Chain Failures

This category covers more than outdated libraries. It includes package sources, transitive
components, build tooling, CI/CD, artifact repositories, compromised suppliers, and the ability to
trace what was built.

Use A03 for:

- unpinned or unmaintained dependencies and actions;
- lockfiles missing or ignored;
- SCA, licence policy, secret, IaC, and container scan placement;
- dependency updates that execute install/build hooks;
- missing SBOM and unknown artifact contents;
- malicious or compromised build dependencies.

### A08:2025 — Software or Data Integrity Failures

This category covers trust without verification: unsigned updates, mutable artifacts, insecure
deserialization, and CI/CD that executes or promotes unverified input.

Use A08 for:

- `pull_request_target` executing fork-controlled code with secrets or a write token;
- artifacts crossing from untrusted to privileged jobs without validation;
- signatures or provenance generated but not verified;
- mutable tags used at deployment;
- missing admission-time verification;
- build steps able to access provenance signing material.

A finding may map to both A03 and A08. Use the primary failure for reporting and name the other as
related rather than duplicating the finding.

## OWASP ASVS 5.0.0

Source: <https://owasp.org/www-project-application-security-verification-standard/>

### V13 — Configuration

Use V13 for pipeline, deploy, dependency, secret, and environment configuration: minimal token
permissions, protected production environments, secret scoping, runner setup, debug logging, and
secure defaults.

### V15 — Secure Coding and Architecture

Use V15 for software supply-chain design and secure development practice: dependency policy,
security testing, build integrity, component inventory, provenance, and vulnerability management.

This skill cites chapters, not individual requirement IDs. ASVS 5.0.0 substantially changed the
numbering from 4.x. For a formal verification, use the official 5.0.0 requirement text and do not
carry old IDs forward.

## CWE

Sources: MITRE CWE definitions, verified 2026-07-28.

| CWE | Exact name | Pipeline use |
|---|---|---|
| CWE-1104 | Use of Unmaintained Third Party Components | Abandoned or unsupported dependencies and build components |
| CWE-506 | Embedded Malicious Code | Malicious payload inserted into a dependency, action, artifact, compiler, or build output |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | Executing third-party actions, install scripts, fork code, or downloaded tooling outside the intended trust boundary |

CWE-829 is often the best implementation-level mapping for an unpinned third-party action or
`pull_request_target` flow. CWE-506 describes malicious code itself; do not use it merely because a
component could become malicious. CWE-1104 concerns maintenance status, not every known CVE.

## Control Map

| Control | OWASP | ASVS | CWE where applicable |
|---|---|---|---|
| Commit lockfiles and install frozen | A03 | V15 | CWE-829, CWE-1104 |
| Pin third-party actions to commit SHA | A03 | V15 | CWE-829 |
| Keep untrusted PR code away from secrets/write token | A08 | V13, V15 | CWE-829 |
| Scope `GITHUB_TOKEN` per job | A08 | V13 | CWE-829 |
| Use cloud OIDC instead of long-lived keys | A03, A08 | V13 | CWE-829 |
| Isolate self-hosted runners | A08 | V13, V15 | CWE-829 |
| Generate SBOM from exact artifact | A03 | V15 | — |
| Sign artifacts and verify at admission | A08 | V15 | CWE-506 |
| Generate and verify provenance | A08 | V15 | CWE-506 |
| Track reachability and remediation SLA | A03 | V15 | CWE-1104 |
| Scan IaC and built images | A03 | V13, V15 | CWE-1104 where component-related |
| Enforce licence policy | A03 | V15 | CWE-1104 where unmaintained components are involved |

## Sources

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS project — <https://owasp.org/www-project-application-security-verification-standard/>
- CWE-1104 — <https://cwe.mitre.org/data/definitions/1104.html>
- CWE-506 — <https://cwe.mitre.org/data/definitions/506.html>
- CWE-829 — <https://cwe.mitre.org/data/definitions/829.html>
