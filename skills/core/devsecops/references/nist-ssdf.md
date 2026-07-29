# NIST SSDF SP 800-218

Version 1.1, published February 2022. Verified 2026-07-28 against
<https://csrc.nist.gov/pubs/sp/800/218/final>.

The Secure Software Development Framework is a set of high-level practices to integrate into an
organization's SDLC. It is not a scanner checklist and it does not prescribe a single CI vendor.

## Practice Groups

| Group | Meaning | DevSecOps application |
|---|---|---|
| PO - Prepare the Organization | Prepare people, processes, and technology | Security roles, policy, tool ownership, training, risk tolerance, and supplier expectations |
| PS - Protect the Software | Protect software from tampering and unauthorized access | Source and artifact access, signing keys, secrets, dependencies, repositories, and build isolation |
| PW - Produce Well-Secured Software | Produce releases with as few security vulnerabilities as possible | Secure coding, reviews, SAST/DAST/SCA, IaC and container testing, SBOM, reproducible inputs |
| RV - Respond to Vulnerabilities | Find, fix, and prevent recurrence | Triage, reachability, severity, SLAs, disclosure, exceptions, regression tests, and lessons learned |

## How to Use SSDF Here

Map the process control to SSDF and the implementation control to OWASP/ASVS. For example:

- a team baselining Semgrep findings and assigning burn-down owners is PW/RV;
- locking dependencies and protecting action/code repositories is PS;
- generating an SBOM and testing the built image is PW;
- an expiring exception with a named approver is RV;
- a security champion and tool owner is PO.

SSDF is outcome-oriented. Do not claim an organization "complies with SSDF" because a workflow
contains a scanner. State the practice, evidence, and remaining gaps.

## Supply Chain Evidence

`A03:2025` · ASVS V13, V15

Useful evidence includes:

- protected repository and workflow settings;
- dependency lockfile and review record;
- scanner version, configuration, baseline, and findings history;
- SBOM tied to a release digest;
- signing and provenance verification logs;
- vulnerability tickets with owner, SLA, remediation, and expiry;
- runner isolation and cloud trust policy review.

Evidence that a tool ran is not evidence that it found every flaw. Record scope, exclusions,
false-positive decisions, and unverified surfaces.

## Limitations

SP 800-218 is a framework of practices, not a prescriptive set of GitHub YAML keys, severity
numbers, or universal SLAs. Use OWASP ASVS 5.0 for application verification and SLSA 1.2 for build
provenance levels. Use the organization's risk policy for remediation deadlines.

## Sources

- NIST SP 800-218 final - <https://csrc.nist.gov/pubs/sp/800/218/final>
- SP 800-218 PDF - <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf>
- NIST SSDF project - <https://csrc.nist.gov/Projects/ssdf>
- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
