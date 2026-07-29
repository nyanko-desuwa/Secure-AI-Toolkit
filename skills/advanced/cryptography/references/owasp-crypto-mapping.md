# OWASP Mapping for Cryptography

Which category and chapter to cite for a crypto finding, and the CWE that goes with it.

Verified 2026-07-28 against <https://owasp.org/Top10/2025/> and
<https://owasp.org/www-project-application-security-verification-standard/>.

## Top 10 2025

`A04:2025 - Cryptographic Failures` is the primary category: data not encrypted where it should be,
or encrypted badly. Weak algorithms, reused IVs, hardcoded keys, homegrown constructions.

Two adjacent categories catch crypto findings that are not really about the maths:

- `A02:2025 - Security Misconfiguration` for TLS configuration, disabled certificate verification,
  and default keys left in place
- `A07:2025 - Authentication Failures` for password storage and token verification, because the
  impact lands on authentication

Note the 2025 renumbering. Cryptographic Failures was A02 in 2021 and is A04 in 2025. A finding
copied forward with its old ID is wrong.

## ASVS 5.0.0 chapters

ASVS 5.0.0 was released 2025-05-30. Requirement IDs do not carry over from 4.x - a `V2.1.1`
citation from a 4.x report means something different now.

| Chapter | Title | Cite it for |
|---|---|---|
| V11 | Cryptography | Algorithm choice, key management, randomness |
| V12 | Secure Communication | TLS configuration, certificate validation |
| V14 | Data Protection | Sensitive data at rest and in transit, retention, PII |
| V6 | Authentication | Password storage, credential recovery |
| V9 | Self-contained Tokens | JWT signature, claims, algorithm pinning |
| V16 | Security Logging and Error Handling | Fail-closed on a decrypt or verify error |

Cite the chapter, not an invented requirement number. `ASVS V11 (Cryptography)` is a correct and
useful citation. A precise requirement ID you have not read is worse than no ID at all - pull it
from <https://github.com/OWASP/ASVS> if you need one.

Levels: state which you targeted. Level 1 is a black-box floor, Level 2 the right default for
business applications handling sensitive data, Level 3 for health, finance, safety, and critical
infrastructure. "ASVS compliant" on its own means nothing.

## CWE lookup

| CWE | Name | Typical shape |
|---|---|---|
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | MD5, RC4, 3DES, DES |
| CWE-328 | Use of Weak Hash | SHA-1 for integrity or signatures |
| CWE-916 | Password Hash With Insufficient Computational Effort | SHA-256 on a password |
| CWE-759 | One-Way Hash without a Salt | `sha256(password)` |
| CWE-329 | Generation of Predictable IV with CBC Mode | static or counter IV in CBC |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption | static IV in GCM |
| CWE-338 | Use of Cryptographically Weak PRNG | `Math.random()` for a token |
| CWE-330 | Use of Insufficiently Random Values | timestamp or sequence as a token |
| CWE-798 | Use of Hard-coded Credentials | key literal in source |
| CWE-321 | Use of Hard-coded Cryptographic Key | same, specifically a crypto key |
| CWE-320 | Key Management Errors | no rotation path, key stored with ciphertext |
| CWE-311 | Missing Encryption of Sensitive Data | plaintext PII at rest |
| CWE-319 | Cleartext Transmission of Sensitive Information | HTTP, plain SMTP, unencrypted DB link |
| CWE-295 | Improper Certificate Validation | `verify=False`, `InsecureSkipVerify: true` |
| CWE-297 | Improper Validation of Certificate with Host Mismatch | chain checked, hostname not |
| CWE-347 | Improper Verification of Cryptographic Signature | JWT `alg` taken from the token |
| CWE-208 | Observable Timing Discrepancy | `==` on an HMAC or a token |
| CWE-696 | Incorrect Behavior Order | verifying a signature after parsing the payload |
| CWE-353 | Missing Support for Integrity Check | AES-CBC with no MAC |
| CWE-326 | Inadequate Encryption Strength | RSA-1024, AES-128 where policy requires 256 |
| CWE-1240 | Use of a Risky Cryptographic Primitive | custom construction from cipher plus hash |

## Writing a finding

Four parts, in this order:

1. What an attacker gets. "A stolen database dump yields every password in hours on one GPU"
2. Where it is. File and line, plus the key or algorithm involved
3. The standard. Category, ASVS chapter, CWE
4. The fix, and what it does not fix

Part 4 is what separates a useful crypto finding from a scanner line. Argon2id fixes offline
cracking speed; it does nothing about a weak password policy or a phished credential. Say both.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/> (checked 2026-07-28)
- OWASP ASVS 5.0.0 -
  <https://owasp.org/www-project-application-security-verification-standard/> (checked 2026-07-28)
- OWASP Cryptographic Storage Cheat Sheet -
  <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
- CWE - <https://cwe.mitre.org/>
