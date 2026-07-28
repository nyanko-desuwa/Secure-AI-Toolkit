# OWASP and ASVS Mapping

> OWASP Top 10 2025 and ASVS 5.0.0 checked 2026-07-29.

| Concern | OWASP | ASVS chapter | CWE examples |
|---|---|---|---|
| Sender/recipient authorization, poisoned links | A01 | V2, V8, V13 | CWE-284, CWE-601 |
| TLS, message privacy, secret-bearing links | A02, A04 | V12, V14 | CWE-295, CWE-319, CWE-532 |
| Template/header injection and provider events | A05, A08 | V4, V5, V15 | CWE-79, CWE-93, CWE-345 |
| Resend/retry abuse and delivery failure | A06, A10 | V11, V13 | CWE-400, CWE-307 |
| Delivery evidence and redaction | A09 | V16 | CWE-778, CWE-532 |

Use chapter-level mapping only; do not invent requirement IDs.

Sources:

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cwe.mitre.org/>
