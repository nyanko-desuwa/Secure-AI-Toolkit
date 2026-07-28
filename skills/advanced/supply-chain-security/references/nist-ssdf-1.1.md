# NIST SSDF — SP 800-218 Version 1.1

> SP 800-218 Version 1.1, published February 2022 (final release dated 2022-02-03). Verified
> 2026-07-28 against <https://csrc.nist.gov/pubs/sp/800/218/final> and
> <https://csrc.nist.gov/Projects/ssdf>.
>
> Full title: "Secure Software Development Framework (SSDF) Version 1.1: Recommendations for
> Mitigating the Risk of Software Vulnerabilities." Supersedes NIST CSWP 13 (2020-04-23).
> DOI <https://doi.org/10.6028/NIST.SP.800-218>. Authors: Murugiah Souppaya (NIST),
> Karen Scarfone (Scarfone Cybersecurity), Donna Dodson.

## Why it is here

SSDF is the framework procurement and US federal software attestation forms point at, so it
is often the standard a customer names. It is process-level: practices, tasks, and notional
implementation examples. It will never tell you to run `npm ci`.

Use SSDF to structure and describe a programme. Use ASVS to verify a codebase. Use SLSA to
make a claim about an artefact.

## The four practice groups, as named

| Group | Name | Concern |
|---|---|---|
| PO | Prepare the Organization | People, process, and technology readiness, at organisation level and sometimes per team or project |
| PS | Protect the Software | "Protect all components of the software from tampering and unauthorized access" |
| PW | Produce Well-Secured Software | Ship releases with as few security flaws as possible |
| RV | Respond to Vulnerabilities | Find remaining flaws in releases, fix them, prevent recurrence |

Each practice is published as Practice (name plus unique ID), Task, Notional Implementation
Example, and Reference.

## IDs read from the source

Only these. SSDF IDs are short and easy to transpose, and the framework grew between the 2020
white paper and 1.1 — do not cite one from memory.

| ID | What it covers |
|---|---|
| PO.1.2 | Document the security requirements that organization-developed software must satisfy |
| PO.5 | "Implement and Maintain Secure Environments for Software Development" — a practice added in version 1.1 |
| PS.3.2 | Collect and share provenance data for all components of software releases |
| PW.1.2 | Track security requirements, risks, and design decisions |

PS.3.2 is the SBOM and provenance hook, and note its wording: provenance for all components
of a release, not just your own build output. A build-time SBOM satisfies it. A scan of a
running container does not — that produces an observation, not provenance.

PO.5 is build-environment hardening stated as an organizational practice. It is the same
argument SLSA Build L3 makes about isolation, which is why "our pipeline is less hardened than
the application it builds" is an SSDF gap as well as an A03 exposure condition.

## Cross-standard mapping

| Concern | OWASP | ASVS 5.0 | SSDF | SLSA |
|---|---|---|---|---|
| Component inventory | A03 | 15.1.2 | PS.3.2 | — |
| Trusted source, no confusion | A03 | 15.2.4 | PW group | — |
| Build environment integrity | A03 | V13 configuration | PO.5 | Build L3 |
| Provenance generation | A08 | — | PS.3.2 | Build L1–L3 |
| Signature verification on consume | A08 | — | PS group | Verifying artifacts |
| Remediation windows | A03 | 15.1.1, 15.2.1 | RV group | — |

Cells naming a group rather than an ID are where the mapping is real but the task number was
not read from the source. Cite the group, not a number you have not opened.

## Honest limitations

- An SSDF claim is an attestation about a process, not evidence about an artefact. A project
  can attest to the framework and still deploy an unsigned build from an unauthenticated
  registry. Ask for the provenance, not the attestation.
- Task IDs beyond the four above were not verified during this check: the CSRC landing page
  does not enumerate them. The SSDF table (Excel) linked from the publication page does — fetch
  it before quoting another ID.
- SP 800-218A extends SSDF to generative AI and dual-use foundation models. Separate document,
  not covered here.

## Sources

- <https://csrc.nist.gov/pubs/sp/800/218/final>
- <https://csrc.nist.gov/Projects/ssdf>
