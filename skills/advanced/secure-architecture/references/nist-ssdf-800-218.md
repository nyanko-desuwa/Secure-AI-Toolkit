# NIST SSDF — SP 800-218

Version: Secure Software Development Framework (SSDF) Version 1.1, NIST SP 800-218, published
February 2022. Supersedes NIST CSWP 13 (April 2020). Tied to Executive Order 14028.

Source: <https://csrc.nist.gov/pubs/sp/800/218/final>
Verified: 2026-07-28. SP 800-218A exists separately as a generative AI profile.

## Why it appears in an architecture skill

SSDF is the framework auditors and procurement teams cite. It says almost nothing about how to
build a secure design, but it does say that designing securely is a required practice with a
name. When a review finding needs to land in a compliance artefact, PW.1 and PW.2 are where
architecture work belongs.

## The four practice groups

| Group | Name | Scope |
|---|---|---|
| PO | Prepare the Organization | People, process, and technology ready to develop securely |
| PS | Protect the Software | Protect components from tampering and unauthorized access |
| PW | Produce Well-Secured Software | Build releases with as few vulnerabilities as possible |
| RV | Respond to Vulnerabilities | Find, fix, and prevent recurrence |

Architecture work concentrates in PW. Threat modeling, design review, and secure design
requirements are PW practices. Boundary and identity controls that protect the build system
itself are PS. Security requirements defined once for the organization — the baseline every
design inherits — are PO.

## Using it honestly

Quote the group, not an invented task number. SSDF practices carry IDs like `PW.1` with tasks
beneath them (`PW.1.1`, and so on) and each task maps to references in the publication's
tables. If you need a specific task ID in a deliverable, read it out of the PDF or the
supplemental Excel table linked from the publication page rather than reconstructing it.

What SSDF will not do:

- It is not prescriptive about method. It does not tell you to use STRIDE, or to draw a data
  flow diagram, or how deep a review should go.
- It has no verification criteria you can pass or fail. For testable statements use ASVS 5.0.
- It is not a maturity model. There are no levels.

## Practical pairing

| Need | Document |
|---|---|
| "We must show secure design is a practice" | SSDF PW, PO |
| "We must show the build system is protected" | SSDF PS, plus SLSA for build integrity |
| "We need testable requirements" | ASVS 5.0 |
| "We need a risk vocabulary for non-specialists" | OWASP Top 10 2025 |
| "We need a trust model for internal traffic" | NIST SP 800-207 |
