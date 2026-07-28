> Verified 2026-07-28 against <https://owasp.org/Top10/2025/>. The 2025 edition is not a
> renumbering of 2021: A03 and A10 are new, and Injection moved from A03 to A05.

# OWASP Top 10 2025

Use this list for cross-reporting. It is a risk ranking, not a mobile requirement set. Use MASVS
for app controls and ASVS for the server endpoint.

| Category | Title | Mobile examples in this skill |
|---|---|---|
| A01 | Broken Access Control | Client-side entitlements, exported components, deep-link state changes |
| A02 | Security Misconfiguration | ATS/NSC exceptions, debug flags, cleartext, release configuration |
| A03 | Software Supply Chain Failures | Analytics/ad SDKs, missing privacy manifests, OTA bundles |
| A04 | Cryptographic Failures | Plain storage, hardcoded keys, weak or absent transport validation |
| A05 | Injection | WebView bridge messages and untrusted platform inputs |
| A06 | Insecure Design | Treating root detection or a client check as an authorization boundary |
| A07 | Authentication Failures | Embedded WebView OAuth, missing PKCE/state, token lifecycle |
| A08 | Software or Data Integrity Failures | Tampered bundles, unsigned OTA updates, release signing |
| A09 | Security Logging and Alerting Failures | Tokens and PII in logs, no signal on refresh-token reuse |
| A10 | Mishandling of Exceptional Conditions | Fail-open trust callbacks, unsafe migration and logout errors |

The most common cross-reporting pairs here are A01, A02, A04, and A07. A mobile finding can have
more than one category; report the category that describes the exploitable path, not every
category that sounds related.

## Sources

- <https://owasp.org/Top10/2025/>
