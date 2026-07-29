# OWASP Top 10 (2025)

Current released version. Verified against <https://owasp.org/Top10/2025/> on 2026-07-28.

The 2021 edition is superseded. If a project's tooling or policy still references 2021
category IDs, note the mapping rather than silently renumbering.

## Categories

### A01:2025 - Broken Access Control

Still first. Authorization is decided in one place and enforced in another, or not at all.

Ask: for every object read or written, where is ownership checked? Is it server-side? Does
it survive an attacker supplying a different ID?

Typical shapes: IDOR, missing function-level checks, client-side-only role gating,
path traversal, CORS misconfiguration granting origin trust.

### A02:2025 - Security Misconfiguration

Moved up. Defaults left in place, debug enabled in production, permissive CORS, verbose
errors, unnecessary features exposed.

Ask: what is different between this config and production? What does an unauthenticated
request see when something breaks?

### A03:2025 - Software Supply Chain Failures

Broader than the old "vulnerable and outdated components". Covers the whole dependency
and build path: package sources, transitive dependencies, build tooling, CI, artefacts.

Ask: are versions pinned? Is the lockfile committed? Who can publish to the registries
you pull from? Is the build reproducible?

### A04:2025 - Cryptographic Failures

Data not encrypted where it should be, or encrypted badly. Weak algorithms, reused IVs,
hardcoded keys, homegrown constructions.

Ask: what is sensitive here, at rest and in transit? Which library primitive is doing the
work, and is it a high-level one?

### A05:2025 - Injection

SQL, NoSQL, OS command, LDAP, XPath, template, and XSS. Untrusted data reaches an
interpreter as code.

Ask: is this a parameterized query or string concatenation? Is output encoded for its
specific sink?

### A06:2025 - Insecure Design

Missing controls that no amount of implementation care fixes. Business logic that assumes
a well-behaved client. Absent rate limiting on an expensive flow.

Ask: what is the abuse case, not the use case? Threat model before coding.

### A07:2025 - Authentication Failures

Credential stuffing possible, weak or missing MFA, broken session invalidation, guessable
recovery flows, weak password storage.

Ask: what happens on logout, on password change, on token theft?

### A08:2025 - Software or Data Integrity Failures

Unsigned updates, insecure deserialization, CI/CD that trusts unverified input, mutable
artefacts.

Ask: is anything deserialized from an untrusted source? Are artefacts verified before use?

### A09:2025 - Security Logging and Alerting Failures

Note the wording: alerting, not just monitoring. Logs that exist but nobody sees, missing
audit trail for security events, or logs that themselves leak secrets.

Ask: if this were exploited, what in the logs would show it? Who is alerted?

### A10:2025 - Mishandling of Exceptional Conditions

New category. Errors swallowed, failing open, inconsistent error handling that leaks
state, unhandled edge cases that leave the system in a partial state.

Ask: does the failure path deny or allow? Is the error message the same for "wrong
password" and "no such user"?

## Mapping from 2021

Approximate, for migrating existing findings:

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
| A10 Server-Side Request Forgery | folded into A01 / A06 - no standalone SSRF category |

SSRF losing its own slot does not make it less important. It is still a common finding;
report it under access control or insecure design with the CWE (CWE-918) attached.

A10:2025 (Mishandling of Exceptional Conditions) has no 2021 predecessor.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-top-ten/>
