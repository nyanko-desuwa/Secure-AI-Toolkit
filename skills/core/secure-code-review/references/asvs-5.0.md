# OWASP ASVS 5.0.0 — for citing a review finding

Application Security Verification Standard, version 5.0.0, released 30 May 2025. Verified
against <https://owasp.org/www-project-application-security-verification-standard/> on
2026-07-28.

This file is the citation view: which chapter goes on a finding. For the full chapter map with
the 4.0.3 migration notes, see `skills/core/owasp/references/asvs-5.0.md`.

## Why a review cites ASVS at all

The Top 10 category tells the reader the shape of the problem. ASVS tells them the standard the
code failed, which is what turns "I think this is wrong" into "this does not meet a published
requirement". In an argument with an author who disagrees, the ASVS chapter is the thing you
point at.

## Chapters

| Chapter | Title | Cite it when the finding is about |
|---|---|---|
| V1 | Encoding and Sanitization | Data reaching an interpreter — SQL, HTML, shell, LDAP, XPath |
| V2 | Validation and Business Logic | Input parsing, allowlists, business rule enforcement |
| V3 | Web Frontend Security | CSP, headers, cookie flags, clickjacking, browser storage |
| V4 | API and Web Service | REST, GraphQL, gRPC surface behaviour |
| V5 | File Handling | Upload, download, path handling, archive extraction |
| V6 | Authentication | Passwords, MFA, recovery, lockout |
| V7 | Session Management | Lifecycle, rotation, timeout, logout |
| V8 | Authorization | Access control decisions and where they are enforced |
| V9 | Self-contained Tokens | JWT and similar — signature, claims, expiry, algorithm |
| V10 | OAuth and OIDC | Delegated auth, PKCE, redirect URI handling |
| V11 | Cryptography | Algorithm choice, key management, randomness |
| V12 | Secure Communication | TLS configuration, certificate validation |
| V13 | Configuration | Build, deploy, dependency, and secret configuration |
| V14 | Data Protection | Sensitive data at rest and in transit, retention, PII |
| V15 | Secure Coding and Architecture | Design-level and supply chain requirements |
| V16 | Security Logging and Error Handling | Audit trail, error behaviour, fail-closed |
| V17 | WebRTC | Peer connections, media, signalling |

## Cite the chapter, not an invented requirement ID

Chapter-level is a correct citation: `ASVS V8 (Authorization)`. Requirement-level is better,
but only if you read the requirement.

Two reasons not to write a requirement number from memory. First, 5.0 renumbered everything —
a `V4.1.3` you remember from a 4.x report points somewhere else now, or nowhere. Second, a
wrong ID is worse than no ID: the author looks it up, finds it says something unrelated, and
stops trusting the rest of the review.

If you need requirement text, pull it from the source rather than recalling it:
<https://github.com/OWASP/ASVS>

## Levels, and what not to claim

L1 is the black-box-testable baseline, L2 is the default for anything holding sensitive data,
L3 is for applications where failure is severe.

A code review does not produce a level. "This handler fails ASVS V8 guidance" is honest. "This
codebase is not ASVS Level 2" claims an assessment you did not run, requirement by requirement,
across the whole application.

## Sink to chapter

Fast lookup while writing findings. Most findings carry one chapter; some genuinely carry two.

| Sink or weakness | Chapters |
|---|---|
| SQL string concatenation | V1, and V2 if input was never validated |
| Dynamic table or column name | V1 |
| `innerHTML` / unescaped template | V1, V3 |
| OS command with `shell=True` | V1 |
| Deserializer on untrusted bytes | V15 |
| Path built from a request parameter | V5 |
| Archive extracted without checking members | V5 |
| Object lookup missing an actor predicate | V8 |
| Handler with no policy attached | V8, V4 |
| Response containing fields the caller may not read | V8, V14 |
| Outbound request to a user-supplied URL | V2, V12 |
| `jwt.verify` without a pinned algorithm | V9 |
| OAuth redirect URI matched by prefix | V10 |
| Password hashed with SHA-256 | V6, V11 |
| Token from a non-cryptographic RNG | V11 |
| `==` comparison on a secret | V11 |
| TLS verification disabled | V12 |
| Secret in source | V13, V14 |
| Cookie without `HttpOnly` / `Secure` / `SameSite` | V3, V7 |
| Session not invalidated on logout | V7 |
| Unpinned dependency | V13, V15 |
| No rate limit on an expensive flow | V2, V4 |
| Authorization denial not logged | V16 |
| `catch` returning the permissive default | V16 |
| Stack trace in a client response | V16 |

## Limitation

This mapping is chapter-level and hand-built. It is a reviewer's aid, not an ASVS assessment
artefact. Formal verification works from the official CSV, requirement by requirement, at a
declared level.

## Sources

- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://github.com/OWASP/ASVS>
