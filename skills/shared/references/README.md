# Shared References

Standards index. One row per standard, with the version, the date it was checked against its
source, and where the detail lives.

Per-skill `references/` directories hold the summaries. This file exists so you can answer
"which edition are we on, and when was that last true" without opening fifteen skills - and so
that a stale pin is visible rather than invisible.

## Two maps live here as well

Standards pins answer "which edition". Two sibling files answer the other two questions a reader
arrives with:

| File | Answers |
|---|---|
| [skill-graph.md](skill-graph.md) | Which skills load together, and in what order. `depends_on` is the column that matters - a skill that assumes another's guidance produces a partial review without it. |
| [standards-matrix.md](standards-matrix.md) | Which skill owns a given standard, category, or CWE. Read backwards from "A03:2025 appeared in this diff" to the skill that covers it. |

Both are generated from the skills themselves and are the authoritative list of skill names. A
name that does not appear in their left-hand column does not exist as a directory.

## Why the dates are here

Category IDs move between editions. An assistant citing "A03 Injection" is working from the
2021 list; in the 2025 edition A03 is Software Supply Chain Failures and Injection is A05. That
mis-mapping survives review because both strings look plausible.

So: every version claim in this repository carries a source URL and a check date. If the date is
old, the claim is suspect. Re-fetch before relying on it, and update the pin in three places
together - the reference file, the table in `AI_INSTRUCTIONS.md`, and the one in the root
`README.md`.

## Primary standards

| Standard | Version | Verified | Source |
|---|---|---|---|
| OWASP Top 10 | 2025 | 2026-07-28 | <https://owasp.org/Top10/2025/> |
| OWASP API Security Top 10 | 2023 | 2026-07-28 | <https://owasp.org/API-Security/editions/2023/en/0x11-t10/> |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28 | <https://owasp.org/www-project-application-security-verification-standard/> |

### OWASP Top 10 2025

A01 Broken Access Control · A02 Security Misconfiguration ·
A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection ·
A06 Insecure Design · A07 Authentication Failures ·
A08 Software or Data Integrity Failures · A09 Security Logging and Alerting Failures ·
A10 Mishandling of Exceptional Conditions

Not a renumbering of 2021. A03 and A10 are new; Injection moved from A03 to A05. Detail and the
2021 => 2025 mapping: `skills/core/owasp/references/owasp-top10-2025.md`.

### OWASP API Security Top 10 2023

API1 Broken Object Level Authorization · API2 Broken Authentication ·
API3 Broken Object Property Level Authorization · API4 Unrestricted Resource Consumption ·
API5 Broken Function Level Authorization · API6 Unrestricted Access to Sensitive Business Flows ·
API7 Server Side Request Forgery · API8 Security Misconfiguration ·
API9 Improper Inventory Management · API10 Unsafe Consumption of APIs

Detail: `skills/core/api-security/references/api-top10-2023.md`.

### OWASP ASVS 5.0.0

V1 Encoding and Sanitization · V2 Validation and Business Logic · V3 Web Frontend Security ·
V4 API and Web Service · V5 File Handling · V6 Authentication · V7 Session Management ·
V8 Authorization · V9 Self-contained Tokens · V10 OAuth and OIDC · V11 Cryptography ·
V12 Secure Communication · V13 Configuration · V14 Data Protection ·
V15 Secure Coding and Architecture · V16 Security Logging and Error Handling · V17 WebRTC

Cite at chapter level. Individual requirement IDs are only used where a skill verified them
against the official source - 5.0.0 renumbered heavily from 4.0.3, so a recalled ID is a guess.
Formal verification needs the official CSV, not this repository.

## Which one to reach for

Three standards, three jobs. Using the wrong one produces an argument that cannot be settled.

| You need to | Use | Because |
|---|---|---|
| Triage risk, or explain to a non-specialist | Top 10 | A ranked list of what usually goes wrong. Ten items, memorable. |
| Review anything with an API surface | API Security Top 10 | Object-level authorization and resource consumption dominate here and the web Top 10 under-weights both. |
| Verify, test, or gate a release | ASVS | Concrete testable requirements organised in chapters. |

Top 10 tells you what usually goes wrong. ASVS tells you what to check. When the two seem to
disagree they do not: implement the ASVS requirement, report with the Top 10 category.

## Weakness taxonomy

| Source | Use for | URL |
|---|---|---|
| CWE | The specific weakness behind a finding | <https://cwe.mitre.org/> |
| CWE Top 25 | Prioritising what to look for first | <https://cwe.mitre.org/top25/> |
| CVSS 4.0 | A numeric severity when one is required | <https://www.first.org/cvss/> |

A CWE names the weakness; a Top 10 category names the risk class. Give both when they add
information, and skip the CWE when no specific one fits rather than reaching for a vague parent.
Some CWE entries are marked DISCOURAGED for mapping - CWE-284 and CWE-285 among them - because
they are too abstract to act on. Prefer the specific child.

Severity in this repository is exploitability plus blast radius, not category name. SQL injection
on an integer cast in an admin-only route is not critical. CVSS is available when a number is
needed for a tracker, but the reasoning is what a reviewer reads.

## Other sources cited by skills

Each lives in the skill that owns it, with its own version and check date. This is a pointer
list, not a second copy of the pins.

| Source | Owned by |
|---|---|
| OWASP Cheat Sheet Series | multiple; each skill links the specific sheet |
| NIST SP 800-63B (digital identity, throttling, breached passwords) | `core/authentication`, `core/brute-force-defense` |
| NIST SP 800-218 SSDF | `core/devsecops` |
| NIST SP 800-207 Zero Trust | `advanced/secure-architecture` |
| NIST SP 800-61 incident handling | `advanced/incident-response` |
| FIPS 203/204/205 post-quantum | `advanced/cryptography` |
| BCP 195 / RFC 9325 TLS | `advanced/network-security`, `core/ssh-server` |
| SLSA, Sigstore, in-toto, CycloneDX, SPDX | `advanced/supply-chain-security` |
| CIS Benchmarks (Docker, Kubernetes, Windows) | `core/docker-security`, `enterprise/kubernetes-security`, `enterprise/windows-security` |
| OWASP MASVS / MASTG, Mobile Top 10 | `enterprise/mobile-security` |
| OWASP Smart Contract Top 10 | `enterprise/blockchain-security` |
| OWASP LLM Top 10 | `core/ai-security` |
| OWASP AISVS 1.0 | `core/ai-security` |

Some of these are deliberately incomplete. Where a document sits behind registration or returned
an error, the skill says what it could not extract instead of filling the gap from memory -
`enterprise/kubernetes-security` omits CIS recommendation IDs for exactly this reason. That gap
is the honest output, not a defect.

## Adding a reference

One file per source, in the owning skill's `references/`. Include:

- Standard name, version, release date if published, and the URL you fetched
- The date you checked it
- Only what the skill actually uses. A reference file is not a mirror of the standard; a 400-line
  recital of a document the reader can open is context spent for nothing
- What you could not verify, named explicitly

Then add a row above if it is a new source, and update the pinned table in `AI_INSTRUCTIONS.md`
and the root `README.md` if it is a primary standard.
