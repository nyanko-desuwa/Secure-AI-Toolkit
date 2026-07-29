# OWASP ASVS 5.0.0

Application Security Verification Standard, version 5.0.0, released 30 May 2025 at Global
AppSec EU Barcelona. This is a significant restructure from 4.0.3 - chapter numbers and
requirement IDs do not carry over, so a `V2.1.1` citation from a 4.x report means something
different in 5.0.

Source: <https://owasp.org/www-project-application-security-verification-standard/>

## What ASVS is for

The Top 10 is a risk list. ASVS is a requirements list. Where the Top 10 says "broken access
control is common", ASVS gives you a specific, testable statement you can pass or fail. Use
Top 10 to decide what to look at, ASVS to decide whether it is correct.

## Chapters

| Chapter | Title | Reach for it when |
|---|---|---|
| V1 | Encoding and Sanitization | Anything reaching an interpreter - SQL, HTML, shell, LDAP |
| V2 | Validation and Business Logic | Input parsing, business rule enforcement, workflow order |
| V3 | Web Frontend Security | CSP, headers, cookies, clickjacking, browser storage |
| V4 | API and Web Service | REST, GraphQL, gRPC surfaces |
| V5 | File Handling | Uploads, downloads, path handling, archive extraction |
| V6 | Authentication | Passwords, MFA, credential recovery, lockout |
| V7 | Session Management | Session lifecycle, rotation, timeout, logout |
| V8 | Authorization | Access control decisions and enforcement points |
| V9 | Self-contained Tokens | JWT and similar. Signature, claims, expiry, algorithm |
| V10 | OAuth and OIDC | Delegated auth flows, PKCE, redirect URI handling |
| V11 | Cryptography | Algorithm choice, key management, randomness |
| V12 | Secure Communication | TLS configuration, certificate validation |
| V13 | Configuration | Build, deploy, dependency, and secret configuration |
| V14 | Data Protection | Sensitive data at rest and in transit, retention, PII |
| V15 | Secure Coding and Architecture | Design-level and supply chain requirements |
| V16 | Security Logging and Error Handling | Audit trails, error behaviour, fail-closed |
| V17 | WebRTC | Peer connections, media, signalling |

Appendices A through E cover glossary, references, cryptography detail, recommendations, and
contributors.

## Notable changes from 4.0.3

Worth knowing if you are carrying over old findings or tooling:

- **Encoding moved to V1.** In 4.x, encoding and validation shared V5. Splitting them makes the
  point that validation and encoding are different controls, not alternatives
- **Self-contained tokens got their own chapter (V9).** JWT problems were scattered across
  session and crypto requirements in 4.x
- **OAuth and OIDC got their own chapter (V10).** Previously thin coverage inside authentication
- **WebRTC added (V17).** New surface, no 4.x equivalent
- **Requirement IDs are not stable across the major version.** Re-map, do not assume

## Levels

ASVS defines verification levels. Pick one and say which you targeted, because "ASVS compliant"
means nothing on its own.

- **Level 1** - the baseline. Achievable by black-box testing. Appropriate for applications with
  no sensitive data. Treat this as a floor, not a goal
- **Level 2** - for applications handling sensitive data. This is the right default for most
  business applications
- **Level 3** - for applications where failure is severe: health, finance, safety, critical
  infrastructure

Do not claim a level you have not verified requirement by requirement. Stating "we followed
ASVS V8 guidance" is honest; "we are ASVS Level 2" implies a completed assessment.

## Using ASVS in a review

Cite the chapter when the finding is general, the requirement when you have checked the specific
statement. `ASVS V8 (Authorization)` is a correct and useful citation. Inventing a precise
requirement number you have not read is worse than citing the chapter.

For anything beyond a chapter-level citation, pull the current requirement text from the
official repository rather than from memory - the 5.0 numbering is new enough that recalled IDs
are unreliable:

<https://github.com/OWASP/ASVS>

## Practical mapping

Which chapter to open, given what the change touches:

| Change touches | Chapters |
|---|---|
| Login, registration, password reset | V6, V7, V14 |
| An API endpoint | V4, V8, V2 |
| A database query | V1, V8 |
| File upload | V5, V8, V13 |
| JWT handling | V9, V11 |
| Third-party login | V10, V9 |
| Rendering user content | V1, V3 |
| Outbound HTTP request | V2, V12 |
| Error handling | V16 |
| Dependency addition | V13, V15 |
