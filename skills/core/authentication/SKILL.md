---
name: authentication
description: 'Design and review identity: password storage, login flows, sessions, JWT, OAuth2/OIDC, MFA, and authorization models. Maps to OWASP Top 10 2025 A07 and A01, ASVS 5.0 V6-V10, and NIST SP 800-63B-4. Triggers: "login", "session", "JWT", "OAuth", "password reset", "MFA", "RBAC", "đăng nhập", "xác thực", "phân quyền".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Authentication and Authorization

Identity is where a small mistake becomes a full compromise. A missing `session.regenerate()`
is one line and gives away every account.

## When to Use

- Writing or reviewing login, registration, logout, or password reset
- Choosing between server-side sessions and stateless tokens
- Adding MFA, passkeys, or a step-up prompt on a sensitive action
- Integrating an OAuth2 or OIDC provider, or acting as one
- Designing an authorization model, or auditing one nobody can explain any more
- Reviewing anything that mints, verifies, or stores a token

## Ownership Boundary

**Owns:** Identity proof, credential and recovery flows, sessions, tokens, delegated access, and
the authorization model across an account lifecycle.

**Does not own:**

| Concern | Route to |
|---|---|
| API endpoint and object-level authorization enforcement | `api-security` |
| Credential, signing-key, and pepper storage or rotation | `secrets-management` |
| Guessing policy, throttling, and lockout controls | `brute-force-defense` |
| Redis/Valkey infrastructure for session and revocation stores | `redis-security` |

## The Two Questions

Every finding in this skill answers one of these:

| Question | Category | ASVS |
|---|---|---|
| Are you who you claim to be? | A07:2025 Authentication Failures | V6, V7, V9, V10 |
| Are you allowed to do this? | A01:2025 Broken Access Control | V8 |

Keep them separate. `@require_login` answers the first and says nothing about the second.
Most breaches labelled "auth bug" are actually the second question never being asked.

## Workflow

### 1. Map the identity lifecycle

Trace one account from creation to deletion and name what happens at each edge:

- Registration — is the identifier verified? Is enumeration possible here too?
- Login — what is compared, how slowly, and how often can it be retried?
- Session establishment — what is issued, where is it stored, when does it die?
- Privilege change — login, password change, role change, impersonation start and end
- Recovery — reset, MFA loss, and the human support path behind both
- Termination — logout, password change, admin disable, credential compromise

Recovery and termination are where real attacks land. Login gets all the attention.

### 2. Pick the primitives before the code

Defaults that need a written reason to deviate from:

| Decision | Default |
|---|---|
| Password hash | Argon2id, `m=19456 KiB, t=2, p=1` |
| Session model | Server-side session with an opaque ID in a cookie |
| Cookie | `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Lax`, plus a CSRF token |
| Access token lifetime | Minutes, not hours |
| Refresh token | Rotating, with reuse detection and family revocation |
| Delegated auth | Authorization code + PKCE `S256`, exact redirect URI match |
| Second factor | WebAuthn/passkey first, TOTP second, SMS last and only with an alternative |
| Authorization | Start with RBAC, add ReBAC when ownership graphs appear |

See [best-practices.md](best-practices.md) for why each one, and what breaks without it.

### 3. Enforce, do not decorate

- Derive the actor from the session on every request. Never from a request body, header,
  or a claim the client can re-issue.
- Rotate the session identifier on every privilege change (ASVS V7, CWE-384).
- Invalidate server-side on logout, password change, MFA change, and reset.
- Fail closed. An unreachable identity provider denies access, it does not skip the check.
- Make responses uniform. Same message, same status, comparable timing for "wrong password",
  "no such user", and "account locked" (CWE-204, CWE-208).

### 4. Verify

Run [checklist.md](checklist.md). Every unchecked item is a fix or a stated limitation.
For auth code specifically, prove the negative cases with tests: a reused reset token, a
session ID captured before login, a token signed with the wrong algorithm.

### 5. Report

Per finding: category, location, the attacker's starting position, the exploitation path,
the fix. "Attacker knows the victim's email address" is a precondition worth stating —
it changes severity.

## Severity

Rank by what the attacker gets and what they need to start.

- **Critical** — account takeover with no prior access. Guessable reset token, JWT
  signature bypass, credential stuffing with no throttle, auth bypass.
- **High** — takeover needing a plausible precondition, or privilege escalation while
  authenticated. Session fixation, missing invalidation after password change, no refresh
  token rotation, IDOR on any user-scoped object.
- **Medium** — narrows an attacker's cost without granting access. User enumeration,
  missing absolute timeout, weak Argon2 parameters, no MFA available.
- **Low** — defence in depth missing with no path. No pepper, `SameSite` unset when a CSRF
  token is already enforced.

Weak password hashing is Critical only if the database is already exposed. Say which
assumption you are pricing in.

## Related Skills

- `owasp-security` — the umbrella standards map and general controls
- `api-security` — token handling at API boundaries, scopes, machine-to-machine auth
- `secure-code-review` — reviewing an existing auth implementation in depth
- `secrets-management` — where the signing keys and peppers actually live
- `redis-security` — ACLs, TLS, persistence, eviction, and failure behavior when sessions or revocation state use Redis/Valkey

## Supporting Files

- [README.md](README.md) — purpose, standards table, limitations, security notes
- [checklist.md](checklist.md) — pre-return verification, grouped by lifecycle stage
- [best-practices.md](best-practices.md) — patterns, each with a vulnerable/fixed pair
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the guidance cannot be applied as written
- [prompts.md](prompts.md) — prompts that produce findings, plus an anti-pattern table
- [references/](references/) — ASVS chapters, NIST SP 800-63B-4, RFC 9700, version-pinned
- [examples/](examples/) — eight vulnerable/fixed pairs with CWE mappings
