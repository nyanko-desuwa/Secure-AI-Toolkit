# Standards Matrix

Which skill cites which standard. Read it in either direction: pick a skill and see what it will
cite at you, or pick a category and find the skill that owns it.

Derived from the 47 production skills on 2026-07-29. The versions are the repository-wide pins in
[README.md](README.md): OWASP Top 10 **2025**, OWASP API Security Top 10 **2023**, OWASP ASVS
**5.0.0**.

## How to read the rows

A cell lists what the skill cites, not what the skill is good at. Three consequences worth knowing
before you use this as a coverage claim:

- **"All ten" or "all seventeen" means aggregator, not depth.** `core/owasp`,
  `advanced/security-testing`, `architecture/hexagonal`, and `core/secure-code-review` enumerate
  the full lists because their job is routing and traversal. For depth on A04, the skill to open is
  `advanced/cryptography`, which cites five categories.
- **A missing ID is not a gap.** `core/api-security` cites no web Top 10 IDs at all; it maps to the
  API list instead, which is the correct mapping for that surface.
- **ASVS is chapter level throughout.** No row here implies requirement-level coverage. 5.0.0
  renumbered heavily from 4.0.3, so a requirement ID quoted from memory is a guess that looks
  verifiable.

## Core

| Skill | Top 10 2025 | API Top 10 2023 | ASVS 5.0 chapters | Other |
|---|---|---|---|---|
| `common-pitfalls` | all ten | API3, API4 | V2, V3, V4, V5, V6, V8, V9, V11, V12, V13, V14, V15, V16 | — |
| `owasp` | all ten | all ten | all seventeen | ISO 27001, PCI DSS, SOC 2 |
| `secure-code-review` | A01, A02, A03, A05, A06, A08, A10 | API1, API3 | all seventeen | — |
| `api-security` | — (maps to the API list) | API1–API7, API9, API10 | V1, V2, V4, V5, V6, V7, V8, V9, V10, V12, V13, V16 | — |
| `mvc-security` | A01, A02, A05, A06 | — | V1, V2, V3, V8, V13, V16 | — |
| `database-security` | A01, A02, A04, A05, A06, A08, A09 | API4 | V1, V2, V8, V11, V12, V13, V14, V15, V16 | — |
| `authentication` | A01, A07 | — | V2, V3, V6, V7, V8, V9, V10, V11, V14, V16 | NIST SP 800-63, 800-63B |
| `brute-force-defense` | A01, A04, A06, A07, A09, A10 | API4, API6 | V2, V4, V6, V7, V8, V11, V16 | NIST SP 800-63B |
| `secrets-management` | A02, A04 | — | V2, V6, V11, V12, V13, V14, V15, V16 | NIST SP 800-57 |
| `publish-safety` | A02, A03, A04, A08 | — | V2, V3, V12, V13, V14, V15, V16 | SLSA |
| `logging-audit` | A01, A05, A06, A09, A10 | — | V7, V16 | GDPR, HIPAA, PCI DSS, ISO 27001, SOC 2 |
| `frontend-security` | A01, A02, A03, A05, A07 | — | all seventeen | — |
| `file-upload-security` | A01, A02, A05, A06, A08, A10 | — | V1, V2, V3, V4, V5, V8, V12, V13, V14, V16 | — |
| `docker-security` | A02, A03, A04, A08 | — | V12, V13, V14, V15, V16 | CIS Docker Benchmark, CIS Kubernetes Benchmark |
| `cloud-security` | A01, A02, A04, A06, A08, A09 | — | V2, V8, V11, V12, V13, V14, V15, V16 | — |
| `ssh-server` | A02, A04, A07, A08, A09 | — | V6, V7, V8, V12, V13, V16 | CIS NGINX Benchmark |
| `devsecops` | A03, A08 | — | V13, V15 | SLSA, NIST SP 800-218 |
| `ai-security` | all ten | — | V1, V2, V5, V8, V10, V11, V13, V14, V15, V16 | OWASP LLM Top 10, NIST AI RMF, EU AI Act |
| `http-edge-security` | A02, A04, A05, A06 | — | V4, V11, V13, V14 | HTTP RFC 9110–9114 |
| `realtime-security` | A01, A04, A05, A07 | API1, API2, API4, API5 | V4, V6, V7, V8, V13 | RFC 6455, WebRTC |
| `redis-security` | A01, A02, A03, A04, A06, A08, A09, A10 | API4 | V2, V6, V7, V8, V11, V12, V13, V14, V15, V16 | Redis OSS, Valkey, MITRE CWE |
| `sso-federation` | A01, A07, A08 | — | V2, V3, V6, V7, V8 | SAML 2.0 |
| `browser-platform-security` | A01, A02, A06, A08 | — | V1, V3, V13, V14 | Service Worker, WebExtensions |
| `deserialization-security` | A05, A06, A08 | — | V2, V5, V13 | CWE-502, CWE-611, CWE-776 |
| `email-security` | A01, A02, A04, A05, A06, A08, A09, A10 | API4, API8, API10 | V2, V4, V6, V7, V8, V11, V12, V13, V14, V15, V16 | RFC 5321, 5322, 6376, 7208, 7489 |
| `http-client-security` | A01, A02, A04, A06, A08, A09, A10 | API4, API7, API8, API10 | V4, V7, V8, V11, V12, V13, V14, V15, V16 | RFC 3986, 9110, 9325; OWASP SSRF Cheat Sheet |

## Advanced

| Skill | Top 10 2025 | API Top 10 2023 | ASVS 5.0 chapters | Other |
|---|---|---|---|---|
| `cryptography` | A02, A04, A07, A08, A10 | — | V2, V6, V9, V11, V12, V14, V16 | FIPS 140, 203, 204, 205; NIST SP 800-38, 800-56A, 800-57, 800-77, 800-90A, 800-131A |
| `network-security` | A01, A02, A04, A06, A09 | — | V1, V2, V6, V12, V13, V16, V17 | NIST SP 800-207 |
| `security-testing` | all ten | API1 | all seventeen | OWASP MASTG |
| `incident-response` | A07, A09, A10 | — | V6, V7, V10, V16 | NIST SP 800-61, 800-86, 800-92, 800-184; NIST CSF; OWASP LLM Top 10 |
| `supply-chain-security` | A03, A08 | — | V13, V14, V15 | SLSA, NIST SP 800-218, 800-218A |
| `secure-architecture` | A01, A02, A06, A09, A10 | — | all seventeen | NIST SP 800-207, 800-218, 800-218A; SLSA; STRIDE; ISO 27001; SOC 2; GDPR |

## Enterprise

| Skill | Top 10 2025 | API Top 10 2023 | ASVS 5.0 chapters | Other |
|---|---|---|---|---|
| `kubernetes-security` | A01, A02, A03, A09 | — | V13, V14, V15, V16 | CIS Kubernetes Benchmark |
| `windows-security` | A01, A02, A04, A09, A10 | — | V1, V12, V13, V14, V16, V17 | NIST SP 800-53 |
| `mobile-security` | A01, A02, A03, A04, A06, A07 | — | V1, V2, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16 | OWASP MASVS, MASTG |
| `blockchain-security` | A01, A04, A06, A08, A10 | — | V1, V2, V4, V8, V11, V13, V14, V15, V16, V17 | — |
| `compliance` | all ten | — | V8, V11, V12, V13, V14, V15, V16 | GDPR, HIPAA, PCI DSS, ISO/IEC 27001, SOC 2 |

## Architecture

The architecture skills cite security categories to explain what a structural decision costs, not
to verify against them. Treat these rows as "this skill will bring up A01" rather than "this skill
covers A01".

| Skill | Top 10 2025 | API Top 10 2023 | ASVS 5.0 chapters | Other |
|---|---|---|---|---|
| `clean-architecture` | A01, A05, A06, A10 | API1, API3, API4 | V2, V7, V8, V14, V15, V16 | — |
| `hexagonal` | all ten | all ten | all seventeen | — |
| `ddd` | A01, A09 | — | V2, V4, V8, V14, V15, V16 | — |
| `cqrs` | A01, A04, A06, A08 | API1, API3, API4 | V1, V2, V8, V11, V14, V15 | GDPR |
| `event-driven` | A01, A02, A04, A06, A07, A08, A09, A10 | — | V2, V6, V8, V11, V12, V13, V14, V15, V16 | — |
| `modular-monolith` | A01, A05, A06, A08, A10 | — | V2, V4, V8, V13, V14, V15, V16 | — |
| `microservices` | A01, A06 | — | V2, V4, V6, V8, V9, V12, V13, V14, V15, V16 | — |
| `design-patterns` | A01, A05, A06, A10 | — | V8, V15, V16 | — |
| `performance` | A01, A02, A06, A09, A10 | API1, API4, API6 | V2, V4, V5, V8, V13, V15, V16 | ISO 27001, PCI DSS, SOC 2 |
| `scalability` | A01, A02, A06, A09, A10 | API4 | V4, V8, V13, V15, V16 | — |

## Category → skill

The direction you usually want. Primary owner first, then the skills that carry part of it.
Aggregators (`owasp`, `secure-code-review`, `security-testing`) cover every row and are omitted
from all of them.

| Top 10 2025 | Primary owner | Also |
|---|---|---|
| A01 Broken Access Control | `core/api-security` | `core/authentication`, `core/mvc-security`, `core/database-security`, `advanced/secure-architecture` |
| A02 Security Misconfiguration | `core/common-pitfalls` | `core/docker-security`, `core/cloud-security`, `core/publish-safety`, `core/ssh-server`, `enterprise/kubernetes-security` |
| A03 Software Supply Chain Failures | `advanced/supply-chain-security` | `core/devsecops`, `core/publish-safety`, `core/docker-security`, `core/frontend-security` |
| A04 Cryptographic Failures | `advanced/cryptography` | `core/secrets-management`, `core/ssh-server`, `core/publish-safety`, `core/database-security` |
| A05 Injection | `core/database-security` | `core/frontend-security`, `core/mvc-security`, `core/ai-security` (prompt injection) |
| A06 Insecure Design | `advanced/secure-architecture` | every `architecture/*` skill, `core/brute-force-defense` |
| A07 Authentication Failures | `core/authentication` | `core/brute-force-defense`, `core/ssh-server`, `advanced/cryptography` |
| A08 Software or Data Integrity Failures | `advanced/supply-chain-security` | `core/devsecops`, `core/publish-safety`, `enterprise/blockchain-security` |
| A09 Security Logging and Alerting Failures | `core/logging-audit` | `advanced/incident-response`, `enterprise/compliance`, `core/cloud-security` |
| A10 Mishandling of Exceptional Conditions | `core/common-pitfalls` | `core/logging-audit`, `architecture/performance`, `advanced/incident-response` |

| Framework | Owned by |
|---|---|
| OWASP API Security Top 10 2023 | `core/api-security` |
| OWASP ASVS 5.0.0 | `core/owasp`, with chapter subsets in most skills |
| OWASP LLM Top 10 | `core/ai-security` |
| OWASP MASVS / MASTG | `enterprise/mobile-security` |
| NIST SP 800-63B | `core/authentication`, `core/brute-force-defense` |
| NIST SP 800-57 | `core/secrets-management`, `advanced/cryptography` |
| NIST SP 800-207 Zero Trust | `advanced/secure-architecture`, `advanced/network-security` |
| NIST SP 800-218 SSDF | `core/devsecops`, `advanced/supply-chain-security` |
| NIST SP 800-61 / 800-184 | `advanced/incident-response` |
| NIST SP 800-53 | `enterprise/windows-security` |
| FIPS 140 / 203 / 204 / 205 | `advanced/cryptography` |
| SLSA | `advanced/supply-chain-security`, `core/devsecops` |
| CIS Benchmarks | `core/docker-security`, `core/ssh-server`, `enterprise/kubernetes-security` |
| GDPR, HIPAA, PCI DSS, ISO 27001, SOC 2 | `enterprise/compliance`, with `core/logging-audit` for the retention and audit-trail parts |

## CWE

Not tabulated per skill. Each skill's `references/` names the CWE entries it uses, with the date
each was fetched from `cwe.mitre.org`, and a per-skill CWE column here would go stale silently
while looking authoritative.

Two entries need care wherever they appear, because MITRE marks them DISCOURAGED for mapping:
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) and CWE-284/CWE-285 (access
control). They are too abstract to act on. Cite the specific child — CWE-527, CWE-538, CWE-540,
CWE-615, CWE-532 for exposure; the concrete authorization weakness for access control.

## Keeping this current

This file is derived, so it drifts when a skill adds a citation. Regenerate the source data rather
than editing rows from memory:

```bash
# Which Top 10 2025, API 2023, and ASVS IDs each skill cites
for f in $(find skills -name SKILL.md ! -path '*skill-scaffold*' | sort); do
  echo "### $(dirname "$f" | sed 's|^skills/||')"
  grep -oE 'A[0-9]{2}:2025' "$f" | sort -u | tr '\n' ' '; echo
  grep -oE 'API[0-9]{1,2}:2023' "$f" | sort -u | tr '\n' ' '; echo
  grep -oE '\bV[0-9]{1,2}\b' "$f" | sort -uV | tr '\n' ' '; echo
done
```

A new skill adds one row to its category table and appears in the `Also` column of every category
it cites. If a version pin changes, it changes in four places together: the owning skill's
reference file, [README.md](README.md), `AI_INSTRUCTIONS.md`, and the root `README.md`.

Companion file: [skill-graph.md](skill-graph.md), for which skills load together rather than which
standards they cite.
