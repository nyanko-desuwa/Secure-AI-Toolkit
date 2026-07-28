# OWASP Verification Checklist

Run before returning code. Mark each item as pass, fail, or not applicable. "Not
applicable" needs a one-line reason — an unexplained skip is a gap.

Only the sections that match the change need running. A CSS fix does not need the crypto
section.

## Access Control (A01 · ASVS V8)

- [ ] Every object read, write, and delete is scoped to the acting user server-side
- [ ] No authorization decision depends on a client-supplied ID, role, or tenant
- [ ] New endpoints deny by default
- [ ] Object-not-yours returns 404, not 403
- [ ] Path and filename inputs cannot traverse outside their intended directory
- [ ] CORS policy names explicit origins. No wildcard with credentials

## Configuration (A02 · ASVS V13)

- [ ] Debug mode and verbose errors off in production paths
- [ ] Default credentials and sample routes removed
- [ ] Security headers set: CSP, HSTS, X-Content-Type-Options, Referrer-Policy
- [ ] Cookies are `HttpOnly`, `Secure`, and `SameSite`
- [ ] No stack traces or internal hostnames in client-facing responses

## Supply Chain (A03 · ASVS V15)

- [ ] New dependencies pinned to exact versions
- [ ] Lockfile updated and committed
- [ ] New package names checked for typosquatting
- [ ] No dependency added for functionality the standard library already provides

## Cryptography and Secrets (A04 · ASVS V11, V14)

- [ ] No secrets in source, tests, fixtures, or comments
- [ ] Secrets read from environment or a secret manager
- [ ] Passwords hashed with Argon2id or bcrypt
- [ ] Random values from a CSPRNG
- [ ] TLS verification enabled
- [ ] Sensitive data encrypted at rest where required

## Injection (A05 · ASVS V1, V2)

- [ ] All queries parameterized. No string concatenation or f-strings in SQL
- [ ] Dynamic identifiers resolved through an allowlist
- [ ] Shell commands use an argument array with `shell=False`
- [ ] Output encoded for its specific sink
- [ ] Template auto-escaping on. Any raw/unsafe helper is justified in a comment
- [ ] Input validated against an allowlist with unknown fields rejected

## Design (A06)

- [ ] Abuse cases considered, not just use cases
- [ ] Rate limiting on expensive or sensitive flows
- [ ] Business rules enforced server-side, not in the client
- [ ] Outbound requests to user-supplied URLs blocked or allowlisted (SSRF, CWE-918)

## Authentication and Session (A07 · ASVS V6, V7)

- [ ] Session invalidated on logout and on password change
- [ ] Session ID rotated on privilege change
- [ ] Login errors uniform. No user enumeration
- [ ] Brute force and credential stuffing throttled
- [ ] Password reset tokens single-use, expiring, and unguessable
- [ ] State-changing requests protected against CSRF

## Integrity (A08)

- [ ] Nothing deserialized from an untrusted source with a code-capable deserializer
- [ ] Uploaded files validated by magic number, not extension or declared MIME type
- [ ] Uploads stored outside the web root and served with a fixed content type

## Logging and Alerting (A09 · ASVS V16)

- [ ] Auth outcomes, authorization denials, and admin actions logged
- [ ] Log entries include actor, action, target, outcome, timestamp
- [ ] Secrets and sensitive fields masked before logging
- [ ] Log output cannot be forged by injecting newlines from user input

## Exceptional Conditions (A10 · ASVS V16)

- [ ] Security checks fail closed
- [ ] No empty `except` or `catch` that swallows a security failure
- [ ] Error messages give the client no internal state
- [ ] Partial failures leave no inconsistent persisted state

## Before Returning

- [ ] Build or compile step run
- [ ] Relevant tests run, with output reported honestly
- [ ] Temporary files removed
- [ ] Documentation updated to match the change
- [ ] Anything unverifiable stated plainly, not implied to be fine
