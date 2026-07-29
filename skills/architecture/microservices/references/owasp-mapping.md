# OWASP and ASVS Mapping

Verified 2026-07-28 against the repository brief. OWASP Top 10 2025 is not a renumbering of 2021; cite the 2025 names. ASVS 5.0.0 is cited at chapter level only.

| Finding shape | OWASP Top 10 2025 | ASVS chapter | Verified CWE |
|---|---|---|---|
| Gateway-only or object-blind authorization | A01 Broken Access Control | V8 Authorization, V4 API and Web Service | CWE-1220 |
| Confused deputy using service privilege for caller | A01, A06 Insecure Design | V8, V15 Secure Coding and Architecture | CWE-441 |
| Trusting client/payload authorization | A01, A06 | V8, V15 | CWE-602 |
| Weak or shared workload credentials | A02 Security Misconfiguration, A07 Authentication Failures | V6 Authentication, V13 Configuration | CWE-290 |
| Shared database erases compartment | A01, A06 | V8, V15 | CWE-653 |
| Arbitrary discovery destination / SSRF | A01, A05 Injection | V4, V15 | CWE-918 |
| Event accepted without integrity or current policy | A01, A08 Software or Data Integrity Failures | V8, V15 | CWE-602 |
| Unbounded pools, queues, retry, cache, or saga | A06, A10 Mishandling of Exceptional Conditions | V2 Validation and Business Logic, V15 | CWE-400, CWE-770, or CWE-772 |
| Missing release of service resources | A10 | V15 | CWE-772 |
| Missing denial/alert on exceptional path | A09 Security Logging and Alerting Failures, A10 | V16 Security Logging and Error Handling | - |

Use one mechanism-specific CWE per finding where possible. Do not attach a CWE merely because the impact sounds similar. A correctness or distributed-consistency defect may have no suitable CWE; say so.

## Reporting distinctions

- Producer: contract carries authority or sensitive data.
- Broker/mesh: identity, ACL, TLS, routing, retention, or live limits.
- Consumer/owner: object policy, schema parsing, idempotency, and failure path.
- Platform: discovery, egress, pool, queue, trace, cache, or breaker controls.

State whether the control is verified in source, inferred, tested, or unverified in the live environment.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>; categories pinned and verified 2026-07-28.
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>; 5.0.0, chapter list pinned and verified 2026-07-28.
- CWE - <https://cwe.mitre.org/>; individual entries in [cwe-microservices.md](cwe-microservices.md).
