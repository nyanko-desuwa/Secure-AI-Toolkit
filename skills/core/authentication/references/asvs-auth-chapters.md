# ASVS 5.0.0 — the identity chapters

Application Security Verification Standard 5.0.0, released 30 May 2025. Five of its
seventeen chapters cover identity. This file summarises what each one is for.

Source: <https://owasp.org/www-project-application-security-verification-standard/>
Requirement text: <https://github.com/OWASP/ASVS>
Verified: 2026-07-28

## Why the chapter split matters

In ASVS 4.x, JWT and OAuth requirements were scattered through the authentication and
session chapters. 5.0 gives self-contained tokens (V9) and OAuth/OIDC (V10) their own
chapters. That is not cosmetic: a JWT is not a session, and delegated authorization is not
authentication. Code that conflates them is the source of most token bugs.

Requirement IDs did not carry over from 4.x. A `V2.1.1` in an old report means something
different in 5.0. Re-map rather than renumber.

## The chapters

| Chapter | Title | Covers |
|---|---|---|
| V6 | Authentication | Password storage and policy, authenticator lifecycle, MFA, credential recovery, throttling and lockout |
| V7 | Session Management | Session ID generation, binding, rotation on privilege change, idle and absolute timeout, logout and termination |
| V8 | Authorization | Where access decisions are made and enforced, deny by default, multi-tenancy separation |
| V9 | Self-contained Tokens | Signature verification, algorithm pinning, issuer and audience validation, expiry, revocation |
| V10 | OAuth and OIDC | Grant selection, PKCE, redirect URI handling, state and nonce, token binding, client authentication |

Supporting chapters you will end up in from here:

| Chapter | Why |
|---|---|
| V3 Web Frontend Security | Cookie attributes, browser storage, CSRF, clickjacking on the login page |
| V11 Cryptography | Which KDF and which signing algorithm, key management |
| V14 Data Protection | Storage of PII gathered at registration |
| V16 Security Logging and Error Handling | Auth event logging, uniform errors, fail closed |

## Citing this honestly

Cite the chapter when the finding is general. `ASVS V7 (Session Management)` is a correct,
defensible citation. A specific requirement number is only worth quoting if you have read
its current text — the 5.0 numbering is new enough that recalled IDs are unreliable, and an
invented ID discredits everything around it.

## Verification levels

- **Level 1** — black-box achievable baseline. A floor, not a target.
- **Level 2** — the right default for anything holding user accounts.
- **Level 3** — health, finance, safety, critical infrastructure.

"We followed ASVS V6 and V7" is honest. "We are ASVS Level 2" implies a completed
requirement-by-requirement assessment. Do not claim the second for the first.

## Mapping to the Top 10 2025

| ASVS chapter | Top 10 2025 category |
|---|---|
| V6 Authentication | A07 Authentication Failures |
| V7 Session Management | A07 Authentication Failures |
| V8 Authorization | A01 Broken Access Control |
| V9 Self-contained Tokens | A07, and A04 when the failure is the algorithm itself |
| V10 OAuth and OIDC | A07, and A06 Insecure Design when the wrong grant was chosen |
