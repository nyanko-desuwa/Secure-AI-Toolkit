# OWASP Verification Checklist

Run before returning code. Mark each item as pass, fail, or not applicable. "Not
applicable" needs a one-line reason - an unexplained skip is a gap.

Only the sections that match the change need running. A CSS fix does not need the crypto
section.

## Access Control (A01 · ASVS V8)

- [ ] [critical] Every object read, write, and delete is scoped to the acting user server-side
- [ ] [critical] No authorization decision depends on a client-supplied ID, role, or tenant
- [ ] [critical] New endpoints deny by default
- [ ] [recommended] Object-not-yours returns 404, not 403
- [ ] [critical] Path and filename inputs cannot traverse outside their intended directory
- [ ] [critical] CORS policy names explicit origins. No wildcard with credentials

## Configuration (A02 · ASVS V13)

- [ ] [critical] Debug mode and verbose errors off in production paths
- [ ] [critical] Default credentials and sample routes removed
- [ ] [recommended] Security headers set: CSP, HSTS, X-Content-Type-Options, Referrer-Policy
- [ ] [critical] Cookies are `HttpOnly`, `Secure`, and `SameSite`
- [ ] [recommended] No stack traces or internal hostnames in client-facing responses

## Supply Chain (A03 · ASVS V15)

- [ ] [recommended] New dependencies pinned to exact versions
- [ ] [recommended] Lockfile updated and committed
- [ ] [critical] New package names checked for typosquatting
- [ ] [optional] No dependency added for functionality the standard library already provides

## Cryptography and Secrets (A04 · ASVS V11, V14)

- [ ] [critical] No secrets in source, tests, fixtures, or comments
- [ ] [recommended] Secrets read from environment or a secret manager
- [ ] [critical] Passwords hashed with Argon2id or bcrypt
- [ ] [critical] Random values from a CSPRNG
- [ ] [critical] TLS verification enabled
- [ ] [recommended] Sensitive data encrypted at rest where required

## Injection (A05 · ASVS V1, V2)

- [ ] [critical] All queries parameterized. No string concatenation or f-strings in SQL
- [ ] [critical] Dynamic identifiers resolved through an allowlist
- [ ] [critical] Shell commands use an argument array with `shell=False`
- [ ] [critical] Output encoded for its specific sink
- [ ] [critical] Template auto-escaping on. Any raw/unsafe helper is justified in a comment
- [ ] [critical] Input validated against an allowlist with unknown fields rejected

## Design (A06)

- [ ] [recommended] Abuse cases considered, not just use cases
- [ ] [recommended] Rate limiting on expensive or sensitive flows
- [ ] [critical] Business rules enforced server-side, not in the client
- [ ] [critical] Outbound requests to user-supplied URLs blocked or allowlisted (SSRF, CWE-918)

## Authentication and Session (A07 · ASVS V6, V7)

- [ ] [critical] Session invalidated on logout and on password change
- [ ] [critical] Session ID rotated on privilege change
- [ ] [critical] Login errors uniform. No user enumeration
- [ ] [recommended] Brute force and credential stuffing throttled
- [ ] [critical] Password reset tokens single-use, expiring, and unguessable
- [ ] [critical] State-changing requests protected against CSRF

## Integrity (A08)

- [ ] [critical] Nothing deserialized from an untrusted source with a code-capable deserializer
- [ ] [critical] Uploaded files validated by magic number, not extension or declared MIME type
- [ ] [critical] Uploads stored outside the web root and served with a fixed content type

## Logging and Alerting (A09 · ASVS V16)

- [ ] [recommended] Auth outcomes, authorization denials, and admin actions logged
- [ ] [recommended] Log entries include actor, action, target, outcome, timestamp
- [ ] [critical] Secrets and sensitive fields masked before logging
- [ ] [critical] Log output cannot be forged by injecting newlines from user input

## Exceptional Conditions (A10 · ASVS V16)

- [ ] [critical] Security checks fail closed
- [ ] [critical] No empty `except` or `catch` that swallows a security failure
- [ ] [recommended] Error messages give the client no internal state
- [ ] [recommended] Partial failures leave no inconsistent persisted state

## Before Returning

- [ ] [critical] Build or compile step run
- [ ] [critical] Relevant tests run, with output reported honestly
- [ ] [recommended] Temporary files removed
- [ ] [critical] Documentation updated to match the change
- [ ] [critical] Anything unverifiable stated plainly, not implied to be fine
