> Verified 2026-07-28 against the OWASP ASVS project page. Version 5.0.0 was released
> 2025-05-30. Source: <https://owasp.org/www-project-application-security-verification-standard/>

# OWASP ASVS 5.0.0

ASVS is the verification standard for the API and service behind a mobile app. This skill cites
chapters, not individual requirement IDs. Do not invent a 5.0 requirement number; the 5.0
restructure means 4.x identifiers do not carry over.

| Chapter | Title | Mobile use |
|---|---|---|
| V1 | Encoding and Sanitization | Deep-link, WebView, and API input reaching a sink |
| V2 | Validation and Business Logic | Action tokens, state changes, workflow order |
| V4 | API and Web Service | Mobile-facing API contracts and error handling |
| V5 | File Handling | Cached files, exports, and local file paths |
| V6 | Authentication | OAuth clients, re-authentication, recovery |
| V7 | Session Management | Refresh rotation, revocation, logout, timeout |
| V8 | Authorization | Server-side entitlement and object ownership |
| V9 | Self-contained Tokens | JWT validation and claims |
| V10 | OAuth and OIDC | Authorization code, PKCE, redirect handling |
| V11 | Cryptography | Key generation, algorithms, nonce handling |
| V12 | Secure Communication | TLS validation and pinning |
| V13 | Configuration | Release flags, backups, dependency config |
| V14 | Data Protection | Tokens, PII, retention, local storage |
| V15 | Secure Coding and Architecture | Trust boundaries, SDKs, resilience design |
| V16 | Security Logging and Error Handling | Secret-free logs, fail-closed decisions |

For this skill, V6, V9, V10, and V14 are the minimum chapter set when reviewing mobile
authentication and tokens. Add V7 for session lifecycle and V8 for server authorization.

Do not claim an ASVS verification level from a static mobile review. A level requires checking
the requirements at that level.
