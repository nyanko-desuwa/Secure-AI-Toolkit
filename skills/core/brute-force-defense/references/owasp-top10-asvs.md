# OWASP Top 10 2025 and ASVS 5.0 - the parts this skill uses

Sources: <https://owasp.org/Top10/2025/> ·
<https://owasp.org/www-project-application-security-verification-standard/> ·
<https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
Verified: 2026-07-28

## Top 10 2025 categories used here

| Category | Why guessing attacks land here |
|---|---|
| A07 Authentication Failures | The primary category. Unlimited or bypassable login, OTP, and recovery attempt handling |
| A06 Insecure Design | The limit was never specified. No attempt budget in the design, no abuse case for the flow |
| A09 Security Logging and Alerting Failures | The attack ran and nobody saw it. No global failure-rate metric, no alert, no response path |
| A04 Cryptographic Failures | The guessable value came from a weak random source |
| A01 Broken Access Control | Enumerable identifiers matter only because authorization is missing. Guessability is not the bug |

The 2025 edition is not a renumbering of 2021. A03 (Software Supply Chain Failures) and A10
(Mishandling of Exceptional Conditions) are new, and Injection moved from A03 to A05. Do not
carry an A03 citation over from a 2021 report.

A10 is worth naming when the limiter fails open on an error. The exceptional condition - Redis
unreachable - is mishandled, and the outcome is unlimited attempts.

## ASVS 5.0.0 chapters used here

| Chapter | Relevance |
|---|---|
| V6 Authentication | Password policy and blocklists, authenticator lifecycle, throttling and lockout |
| V16 Security Logging and Error Handling | Auth event logging, uniform errors, fail-closed behaviour |
| V7 Session Management | Termination after a successful guess |
| V11 Cryptography | Random source for tokens and codes, constant-time comparison |

Chapter-level citations only. ASVS 5.0.0 renumbered requirements from 4.0.3, so a recalled ID
such as `V2.2.1` is unreliable. If a project needs requirement-level verification, pull the
current text from <https://github.com/OWASP/ASVS> and cite what you read.

## API Security Top 10 2023

| Category | Relevance |
|---|---|
| API4 Unrestricted Resource Consumption | The closest API-specific match for a missing attempt cap. Covers batch endpoints and one-request-many-attempts abuse |
| API2 Broken Authentication | Unthrottled credential and token verification on an API surface |
| API6 Unrestricted Access to Sensitive Business Flows | Coupon codes, invite codes, and referral flows abused at volume |

`core/api-security` owns API4 in depth. This skill cites it and does not repeat it.

## How to cite in a finding

Name the Top 10 category for the reader, the ASVS chapter for the verifier, and the CWE for
precision. "No attempt cap on OTP verification (A07:2025 · ASVS V6 · CWE-307)" is defensible.
"OWASP violation" is not.
