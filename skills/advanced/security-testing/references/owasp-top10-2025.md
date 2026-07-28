# OWASP Top 10 2025, from a testing angle

Current released edition. Verified against <https://owasp.org/Top10/2025/> on 2026-07-28.

2025 is not a renumbering of 2021. A03 (Software Supply Chain Failures) and A10 (Mishandling of
Exceptional Conditions) are new, Injection moved from A03 to A05, and SSRF lost its standalone
slot. If your CI dashboard still groups findings by 2021 IDs, map deliberately rather than
assuming the numbers mean the same thing.

## What each category needs from a suite

### A01:2025 — Broken Access Control

The most testable category, and the one where a matrix pays off immediately. Every object
access is a grid cell: actor, target owner, operation, expected status.

Tests: matrix-generated integration tests per resource. Read, list, update, delete, and every
side-channel operation (export, share, webhook, print). WSTG-ATHZ-02, WSTG-ATHZ-03,
WSTG-ATHZ-04. ASVS V8.

Automatable: almost entirely. A DAST tool cannot do it, because it does not know who owns what,
which is why this belongs in your own suite.

### A02:2025 — Security Misconfiguration

Tests: DAST baseline for headers and TLS, plus CI checks on config files and IaC. Assertions on
cookie flags belong in an integration test, because they are set by application code.
WSTG-CONF-*, WSTG-SESS-02. ASVS V13, V3.

Automatable: yes, but only against a deployed instance. A unit test cannot see whether the
reverse proxy strips the header you set.

### A03:2025 — Software Supply Chain Failures

Tests: dependency scanning and lockfile verification in CI, not application tests. Assert the
lockfile is present and unchanged by the build, and that no dependency was added with a floating
range. ASVS V13, V15.

Automatable: yes. This one is entirely a pipeline concern.

### A04:2025 — Cryptographic Failures

Tests: unit tests on the primitive choice — that a password verifier rejects a hash produced by
a fast hash, that a token generator draws from a CSPRNG, that a comparison is constant-time
(assert the function used, not the timing). WSTG-CRYP-04. ASVS V11, V14.

Automatable: partly. Algorithm choice is testable; key management is a review question.

### A05:2025 — Injection

Tests: behavioural integration tests (did the injected condition change the result set?), unit
tests on the encoder, property tests over the input space, browser tests for XSS.
WSTG-INPV-01, WSTG-INPV-02, WSTG-INPV-05, WSTG-CLNT-01. ASVS V1, V2.

Automatable: yes, and DAST is genuinely good at it. Still write your own tests for the
parameters DAST cannot reach behind multi-step auth.

### A06:2025 — Insecure Design

Tests: abuse-case tests. Rate limits, workflow order, replay, concurrency. These are the tests
nobody writes, because they do not correspond to a line of code. WSTG-BUSL-*. ASVS V2.

Automatable: barely. Derivation is manual; once derived, the test is ordinary.

### A07:2025 — Authentication Failures

Tests: lockout, uniform error responses, session invalidation on logout and password change,
reset token single use and expiry, session rotation on privilege change. WSTG-ATHN-*,
WSTG-IDNT-04, WSTG-SESS-06. ASVS V6, V7.

Automatable: yes. This is a large, well-defined set of integration tests and worth building
once properly.

### A08:2025 — Software or Data Integrity Failures

Tests: upload tests with real file bytes, deserialization tests with a hostile payload, archive
extraction tests with a traversal entry. WSTG-BUSL-08, WSTG-BUSL-09. ASVS V5, V15.

Automatable: yes, and the fixtures are the work. Generate them in the test, do not commit a
malicious binary.

### A09:2025 — Security Logging and Alerting Failures

Tests: assert the audit record exists after a security-relevant action, and assert secrets are
absent from it. The second assertion is the one people skip. ASVS V16.

Automatable: yes, by capturing the log in the test. Alerting is not testable from a suite; that
is a runbook exercise.

### A10:2025 — Mishandling of Exceptional Conditions

New in 2025, and the most under-tested category. Tests: make the dependency fail and assert the
security decision denies. Fault injection, not payloads. WSTG-ERRH-01. ASVS V16.

Automatable: yes, with a mock or a fault-injection proxy. See
[best-practices.md](../best-practices.md#ci-execution) for keeping a deliberate network failure
from reading as a passing control.

## Coverage table

A suite's honest status by category. Fill it in per project; leaving a row blank is more useful
than a coverage percentage.

| Category | Test type | Where | Covered |
|---|---|---|---|
| A01 | Matrix integration | `tests/security/authz/` | |
| A02 | DAST baseline + config check | pipeline | |
| A03 | Dependency scan | pipeline | |
| A04 | Unit | `tests/security/crypto/` | |
| A05 | Integration + property + browser | `tests/security/injection/` | |
| A06 | Abuse-case integration | `tests/security/abuse/` | |
| A07 | Integration | `tests/security/auth/` | |
| A08 | Integration with real bytes | `tests/security/upload/` | |
| A09 | Log-capturing integration | `tests/security/logging/` | |
| A10 | Fault injection | `tests/security/failure/` | |

## Mapping from 2021, for old findings

| 2021 | 2025 |
|---|---|
| A01 Broken Access Control | A01 Broken Access Control |
| A02 Cryptographic Failures | A04 Cryptographic Failures |
| A03 Injection | A05 Injection |
| A04 Insecure Design | A06 Insecure Design |
| A05 Security Misconfiguration | A02 Security Misconfiguration |
| A06 Vulnerable and Outdated Components | A03 Software Supply Chain Failures (broadened) |
| A07 Identification and Authentication Failures | A07 Authentication Failures |
| A08 Software and Data Integrity Failures | A08 Software or Data Integrity Failures |
| A09 Security Logging and Monitoring Failures | A09 Security Logging and Alerting Failures |
| A10 Server-Side Request Forgery | no standalone category; report under A01 or A06 with CWE-918 |

A10:2025 has no 2021 predecessor, which is a reasonable explanation for why almost no existing
suite has tests for it.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://owasp.org/www-project-web-security-testing-guide/v42/>
