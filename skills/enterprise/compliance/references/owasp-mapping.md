# OWASP Mapping Baseline

Checked: 2026-07-28

Sources fetched:

- OWASP Top 10:2025: <https://owasp.org/Top10/2025/>
- OWASP ASVS project: <https://owasp.org/www-project-application-security-verification-standard/>

The project brief pins ASVS 5.0.0 and the OWASP project page confirms it as the latest stable
version. This reference uses chapter-level ASVS mappings only; individual ASVS requirement IDs
are not asserted unless verified in a dedicated source.

## Top 10:2025 categories used here

| ID | Title |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

## Chapter-level ASVS mapping used by this skill

The project-pinned ASVS 5.0.0 chapter names are:

- V8 Authorization
- V11 Cryptography
- V12 Secure Communication
- V13 Configuration
- V14 Data Protection
- V15 Secure Coding and Architecture
- V16 Security Logging and Error Handling

These are verification directions, not a claim that any implementation satisfies the chapter.

## Control mapping

- Access control: A01:2025 and ASVS V8.
- Encryption and key handling: A04:2025 and ASVS V11/V12/V14.
- Secrets rotation: A04:2025 and ASVS V13/V14.
- Vulnerability and supply-chain gates: A03:2025 and ASVS V15.
- Audit logging: A09:2025 and ASVS V16.
- Fail-closed policy and recovery errors: A10:2025 and ASVS V16.

## Deliberate omissions

No ASVS 5.0.0 requirement identifier such as V8.x or V16.x is cited here. The fetched project page
confirmed the stable release but did not expose the detailed chapter text. Fetch and verify the
specific requirement before adding it to an audit mapping.
