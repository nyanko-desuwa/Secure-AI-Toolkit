---
name: brute-force-defense
description: 'Defend against guessing attacks: login brute force, credential stuffing, password spraying, OTP and token guessing, and the limiters that are supposed to stop them. Maps to OWASP Top 10 2025 A07, A06, A09 and ASVS 5.0 V6/V16. Triggers: "brute force", "credential stuffing", "password spraying", "rate limit", "lockout", "OTP", "throttling", "dò mật khẩu", "giới hạn đăng nhập".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Brute Force Defense

This skill owns one attack class: finding a secret by trying candidates. Passwords, OTP codes,
reset tokens, API keys, invite codes, coupon codes, object IDs, HMAC bytes. If it can be
guessed, it belongs here.

It does not cover password hashing (`cryptography`) or session design (`authentication`). It
covers the limiter, the detection, and the guessable surfaces nobody owns.

## When to Use

- Adding or reviewing a rate limiter, lockout policy, or CAPTCHA gate
- Writing an OTP, MFA, password reset, or email verification flow
- Generating any token, code, or identifier a stranger might try to guess
- Investigating a spike in login failures, or a suspected account takeover
- Reviewing a second login path: mobile API, legacy endpoint, SSO callback, password grant
- Anywhere one HTTP request can carry many attempts: GraphQL, gRPC, JSON-RPC, batch endpoints

## Name the Attack First

These get conflated constantly, and a control that stops one does nothing against another.

| Attack | Shape | What defeats it |
|---|---|---|
| Brute force | Many passwords, one account | Per-account limits |
| Credential stuffing | One password per account, thousands of accounts, breached pairs | Breached-password check, MFA, device and global signals |
| Password spraying | Three to five common passwords across every account in a directory | Global failure-rate monitoring, not per-account counters |
| Reverse brute force | One leaked password, many usernames | Same as spraying |
| Offline cracking | Attacker already has the hashes | KDF cost. Rate limiting is irrelevant |

Per-account lockout stops row one and is useless against row three. A sprayer sends three
attempts per account and never trips a counter threshold of five. This is the most common
reasoning error in the area: teams ship a per-account limiter, call brute force solved, and
remain fully open to the attack that is actually used against them.

Offline cracking is in the table so you stop reaching for rate limiting when the hash has
already leaked. Nothing you do at the edge affects an attacker running hashcat locally.

## Workflow

### 1. Enumerate the guessable surfaces

List every endpoint that compares a client-supplied value against a secret, and every value
you generate that someone might guess. Then ask, for each one: how many attempts per minute
can one attacker make, and how large is the candidate space?

A six-digit OTP with no attempt cap is 10^6 candidates and unlimited tries. That is not a
second factor.

See [best-practices.md](best-practices.md#the-surfaces-people-forget).

### 2. Choose dimensions, not a number

A limiter is a set of counters, not one counter. Account, IP, subnet or ASN, device
fingerprint, and a global floor. Each dimension alone has a documented bypass. See
[best-practices.md](best-practices.md#limit-on-several-dimensions-at-once).

### 3. Make the counter real

- Shared storage, atomic operations. A per-process dictionary is not a limit across four pods.
- Normalised keys, or the limit is bypassed by changing capitalisation.
- Fail closed. A Redis outage must not mean unlimited attempts.
- Graduated friction, not a hard lock. Lockout is a DoS lever (CWE-645).

### 4. Count attempts, not requests

One GraphQL request with 500 aliased `login` fields is 500 attempts and one increment. Batch
endpoints, JSON-RPC arrays, and gRPC streams have the same shape. Increment inside the
resolver, not in the HTTP middleware.

### 5. Detect what limits cannot stop

Low-and-slow spraying stays under every per-account threshold by design. It is visible only in
aggregate: elevated global failure rate, many distinct accounts per source, unusual
success-after-failure ratio. See [best-practices.md](best-practices.md#detection).

### 6. Treat success as a compromise

If guessing worked, the account is breached and the attacker may have already changed the
recovery path. Revoke sessions, force a reset, audit for attacker-made changes, notify.
Cross-link `advanced/incident-response`.

## Severity

Rank by candidate space, attempts available, and what a hit is worth.

- **Critical** — an unauthenticated endpoint with a small candidate space and no cap: OTP
  verification, reset token submission, MFA code entry. Account takeover in minutes.
- **High** — login with a bypassable limiter (per-IP only, per-process only, fails open), or
  no breached-password check on an account base with no MFA.
- **Medium** — limiter present but on one dimension, no global failure-rate monitoring, no
  alerting on spraying patterns, enumerable sequential IDs behind valid authorization.
- **Low** — missing defence in depth with no path: no CAPTCHA, no device fingerprinting, when
  the multi-dimensional limiter and MFA are already in place.

A hard per-account lockout with no self-service recovery is a High availability finding, not a
security win. Say which side of the tradeoff you are reporting.

## Related Skills

- `authentication` — password storage, uniform login errors, session and token design
- `advanced/cryptography` — KDF cost, which is the only defence against offline cracking
- `api-security` — resource consumption at the API boundary (API4:2023)
- `logging-audit` — what to log, and what must never reach a log
- `advanced/incident-response` — the response path once guessing succeeded
- `ssh-server` — `MaxAuthTries`, `LoginGraceTime`, `PerSourcePenalties` for SSH specifically
- `redis-security` — ACL, TLS, persistence, eviction, and outage behavior of Redis/Valkey limiter stores

## Supporting Files

- [README.md](README.md) — purpose, standards table, configuration, limitations
- [checklist.md](checklist.md) — pre-return verification, grouped by surface
- [best-practices.md](best-practices.md) — patterns, each with a vulnerable/fixed pair
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the guidance cannot be applied as written
- [prompts.md](prompts.md) — prompts that produce findings, plus an anti-pattern table
- [references/](references/) — OWASP, ASVS, NIST SP 800-63B-4, CWE, version-pinned
- [examples/](examples/) — eight vulnerable/fixed pairs with CWE mappings
