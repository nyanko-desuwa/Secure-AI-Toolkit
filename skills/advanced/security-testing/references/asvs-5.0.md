# OWASP ASVS 5.0.0

Application Security Verification Standard, version 5.0.0, released 30 May 2025. Verified
against <https://owasp.org/www-project-application-security-verification-standard/> on
2026-07-28.

5.0 is a restructure of 4.0.3, not a renumbering. Chapters moved and requirement IDs do not
carry over, so a `V5.3.4` citation in an old test name means something different now. Re-map
before reusing an old suite's citations.

## Why cite ASVS in a test

ASVS is the only one of the three OWASP documents phrased as a verifiable statement. The Top 10
gives you a category and WSTG gives you a procedure; ASVS gives you the property the assertion
should encode.

Practically: WSTG tells you to send `../../etc/passwd`, ASVS tells you the property is that no
input escapes the intended directory. The second is what the test asserts, which is why a test
citing ASVS tends to be written as a property rather than a payload match.

## Chapters

| Chapter | Title | Test layer that usually covers it |
|---|---|---|
| V1 | Encoding and Sanitization | Unit tests on the encoder, plus browser tests for XSS |
| V2 | Validation and Business Logic | Property tests, integration tests for workflow order |
| V3 | Web Frontend Security | Browser tests and DAST for headers, cookies, CSP |
| V4 | API and Web Service | Integration tests against the HTTP surface |
| V5 | File Handling | Integration tests with real file bytes, property tests on paths |
| V6 | Authentication | Integration tests: lockout, reset, credential handling |
| V7 | Session Management | Integration tests: logout, rotation, timeout |
| V8 | Authorization | Matrix-generated integration tests |
| V9 | Self-contained Tokens | Unit tests on verification, plus tampered-token integration tests |
| V10 | OAuth and OIDC | Integration tests against the flow, state and PKCE handling |
| V11 | Cryptography | Unit tests on algorithm choice, randomness, key handling |
| V12 | Secure Communication | TLS scanning, not application tests |
| V13 | Configuration | CI checks on config and IaC, plus DAST |
| V14 | Data Protection | Integration tests on responses, log assertions |
| V15 | Secure Coding and Architecture | Dependency and supply chain checks in CI |
| V16 | Security Logging and Error Handling | Integration tests on error shape and audit records |
| V17 | WebRTC | Not covered by this skill |

Appendices A to E cover glossary, references, cryptography detail, recommendations, and
contributors.

## Levels, and what they mean for a suite

- Level 1 — baseline, verifiable by black-box testing. Treat as a floor.
- Level 2 — for applications handling sensitive data. The right default for most business
  applications.
- Level 3 — for applications where failure is severe: health, finance, safety, critical
  infrastructure.

Level 1 is the level a DAST baseline scan can speak to, because it is defined as black-box
verifiable. Levels 2 and 3 need code access and integration tests, which is the argument for
owning the suite rather than buying a scan.

Do not claim a level from a green suite. "We have integration tests covering ASVS V8" is
honest. "We are ASVS Level 2" implies a requirement-by-requirement assessment.

## Citing ASVS without inventing an ID

Cite the chapter unless you have read the specific requirement text. `ASVS V8 (Authorization)`
is correct, useful, and checkable. A fabricated `V8.2.7` is worse than no citation, because a
reader may act on it.

For requirement-level citations, pull the current text from the official repository rather than
from memory — 5.0 numbering is new enough that recalled IDs are unreliable:

<https://github.com/OWASP/ASVS>

## Notable changes from 4.0.3

- Encoding split into its own chapter (V1). In 4.x it shared a chapter with validation, which
  encouraged treating them as alternatives. They are not: validation shrinks the input space,
  encoding makes the sink safe, and a suite needs tests for both.
- Self-contained tokens got V9. JWT requirements were previously scattered across session and
  crypto chapters.
- OAuth and OIDC got V10.
- WebRTC added as V17.
- Requirement IDs are not stable across the major version.

## Sources

- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://github.com/OWASP/ASVS>
