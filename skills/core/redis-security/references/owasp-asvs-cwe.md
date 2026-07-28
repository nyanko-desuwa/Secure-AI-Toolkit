# OWASP, ASVS, and CWE Mapping

> OWASP Top 10 2025 and ASVS 5.0.0 checked 2026-07-28. CWE catalogue checked 2026-07-28.

## Mapping used by this skill

| Concern | OWASP Top 10 2025 | ASVS 5.0 chapter | CWE examples |
|---|---|---|---|
| Public listener, broad ACL, admin command access | A01 Broken Access Control; A02 Security Misconfiguration | V2 Authentication, V13 Configuration | CWE-284, CWE-269, CWE-306 |
| Plaintext or unverifiable TLS; backups/snapshots | A02; A04 Cryptographic Failures | V12 Secure Communication, V14 Data Protection | CWE-295, CWE-312, CWE-319 |
| Eviction, unbounded keys/Streams/clients, retry storms | A06 Insecure Design; A10 Mishandling of Exceptional Conditions | V8 Data Protection, V11 Business Logic, V13 Configuration | CWE-400, CWE-770 |
| Unsafe module/function/script supply chain or behavior | A03 Software Supply Chain Failures; A08 Software or Data Integrity Failures | V13 Configuration, V15 Secure Coding and Architecture | CWE-829, CWE-94 |
| Sensitive command diagnostics in logs | A09 Security Logging and Alerting Failures | V7 Error Handling and Logging, V16 Security Logging and Error Handling | CWE-532, CWE-778 |

These are chapter-level mappings. Do not invent ASVS requirement IDs from memory.

## Questions implied by the mappings

- **A01/A02:** Can a client outside its intended role reach this listener, key family, channel, command, or configuration surface?
- **A04/V12/V14:** Can credentials or protected data be intercepted, copied into persistence, or read from backups/logs?
- **A06/A10:** Does memory pressure, retry behavior, eviction, or failover silently remove a control or exhaust service capacity?
- **A03/A08:** Is every enabled module/function/script reviewed, patched, and constrained to the keys and commands it needs?
- **A09/V7/V16:** Would an investigation detect abuse without leaking the sensitive values being investigated?

## CWE sources

- <https://cwe.mitre.org/data/definitions/284.html>
- <https://cwe.mitre.org/data/definitions/269.html>
- <https://cwe.mitre.org/data/definitions/306.html>
- <https://cwe.mitre.org/data/definitions/295.html>
- <https://cwe.mitre.org/data/definitions/312.html>
- <https://cwe.mitre.org/data/definitions/319.html>
- <https://cwe.mitre.org/data/definitions/400.html>
- <https://cwe.mitre.org/data/definitions/770.html>
- <https://cwe.mitre.org/data/definitions/532.html>
- <https://cwe.mitre.org/data/definitions/778.html>
- <https://cwe.mitre.org/data/definitions/798.html>
