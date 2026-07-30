# Authentication Verification Checklist

Mark pass, fail, or not applicable. An N/A needs a reason. These checks map to OWASP Top 10
2025 A07 (authentication) or A01 (authorization), ASVS V6-V10, and the CWE shown.

## Passwords and Login - A07 · V6 · CWE-256, CWE-307

- [ ] [critical] Passwords use Argon2id; bcrypt is used only where Argon2 is unavailable
- [ ] [recommended] Argon2id cost is measured on production-class hardware and is not weakened to hide latency
- [ ] [critical] Every password hash has a unique salt; no SHA-256, SHA-1, MD5, or encryption is used as a password store
- [ ] [recommended] A pepper, if used, lives in a vault/HSM outside the password database; rotation cost is documented
- [ ] [recommended] Password input is not silently truncated; the system accepts at least 64 characters
- [ ] [recommended] Passwords are checked against a breached/common-password blocklist
- [ ] [optional] No arbitrary composition rule or periodic forced rotation is imposed; reset follows evidence of compromise
- [ ] [recommended] Unknown user and wrong password take the same verification path and return the same response
- [ ] [recommended] Authentication failures do not reveal whether an account exists, is disabled, or is locked
- [ ] [recommended] Throttling covers account, source IP, device/fingerprint, and distributed credential-stuffing patterns
- [ ] [recommended] Lockout cannot be used as an unauthenticated denial-of-service against a victim
- [ ] [recommended] Passwords, tokens, and request bodies containing them never reach logs

## Sessions and Cookies - A07 · V7 · V3 · CWE-384, CWE-613, CWE-352

- [ ] [critical] Session IDs come from a CSPRNG and contain at least 64 bits of entropy; custom IDs use 128 bits
- [ ] [critical] The session ID is rotated and the pre-authentication ID destroyed after login
- [ ] [recommended] Session ID rotation also happens after password/MFA/role changes and impersonation start
- [ ] [critical] Logout invalidates server-side state, not just the browser cookie
- [ ] [critical] Password change, reset, MFA removal, admin disable, and compromise invalidate relevant sessions
- [ ] [recommended] Idle and absolute timeouts are enforced server-side; absolute lifetime exists even with activity
- [ ] [critical] Session cookies use `HttpOnly` to block script reads, `Secure` to require HTTPS, and explicit `SameSite`
- [ ] [critical] `SameSite=Lax` is paired with a CSRF token for state-changing requests; it is not treated as CSRF protection alone
- [ ] [recommended] Cookie scope is narrow; prefer `__Host-`, no `Domain`, and `Path=/`
- [ ] [recommended] Session, access, refresh, and reset tokens are not stored in browser localStorage/sessionStorage
- [ ] [recommended] Sensitive actions require recent authentication or a step-up factor

## JWT and Self-contained Tokens - A07 · V9 · V11 · CWE-347

- [ ] [critical] The accepted algorithm is a server-side allowlist, never read from the JWT header
- [ ] [critical] Key type and algorithm cannot be confused (for example, an RSA public key is never accepted as an HMAC secret)
- [ ] [critical] Signature is verified before claims are trusted
- [ ] [critical] `iss`, `aud`, `exp`, `nbf`, and any required subject/tenant claims are validated
- [ ] [critical] Key selection is constrained to a trusted issuer/JWKS and safe key IDs; `jku`/`x5u` are not fetched blindly
- [ ] [critical] Token scope is checked against the requested action, not just token validity
- [ ] [recommended] Revocation design is explicit; JWT logout is not claimed to be immediate without server state
- [ ] [critical] Refresh tokens rotate, detect reuse, revoke the token family, and are invalidated on password change/logout

## OAuth2 and OIDC - A07 · A06 · V10 · CWE-601

- [ ] [critical] Authorization code with PKCE `S256` is used; implicit and password grants are absent
- [ ] [critical] `state` binds the browser transaction; OIDC also validates a nonce
- [ ] [critical] Redirect URIs use exact registered string matching; no wildcard or loose prefix matching
- [ ] [critical] Authorization codes are single-use, short-lived, and bound to the client and PKCE verifier
- [ ] [recommended] Tokens do not appear in URLs, browser history, referrer headers, or application logs
- [ ] [recommended] Browser token storage choice is documented; prefer a BFF or secure, HttpOnly cookie session
- [ ] [critical] Scopes, issuer, audience, and token endpoint authentication are validated

## MFA and Recovery - A07 · V6 · CWE-308, CWE-640

- [ ] [recommended] WebAuthn/passkeys are offered for phishing resistance; TOTP is a fallback, not the only option for high risk
- [ ] [recommended] SMS/PSTN is treated as restricted and weakest; an unrestricted alternative is available
- [ ] [critical] MFA enrollment requires an existing authenticated factor and confirmation of the new factor
- [ ] [critical] MFA removal and replacement require step-up authentication and alert the user
- [ ] [critical] Recovery codes are high-entropy, shown once, stored hashed, and single-use
- [ ] [critical] Lost-factor recovery has the same scrutiny as login and does not rely on a weak help-desk bypass
- [ ] [recommended] Reset and recovery events notify the user through an independent channel

## Password Reset - A07 · V6/V7 · CWE-640

- [ ] [recommended] Request response is identical whether the email/username exists
- [ ] [critical] Reset token is generated by a CSPRNG, is high entropy, single-use, short-lived, and stored hashed
- [ ] [critical] Token is not derived from user ID, timestamp, counter, or password hash
- [ ] [recommended] Token is never logged or placed in analytics/referrer-visible URLs beyond the required link
- [ ] [critical] A successful reset invalidates existing sessions, refresh-token families, and prior reset tokens
- [ ] [recommended] New password passes length and breached-password checks

## Authorization, Impersonation, and Audit - A01 · V8 · V16 · CWE-862, CWE-639

- [ ] [critical] Authorization is deny-by-default and enforced server-side at the object and function boundary
- [ ] [critical] Actor, tenant, role, and resource are derived or looked up server-side, not trusted from the client
- [ ] [recommended] RBAC, ABAC, or ReBAC choice is documented; policy rules have one auditable enforcement layer
- [ ] [critical] Every read, write, delete, export, and admin action checks authorization
- [ ] [critical] Impersonation requires explicit privileged authorization, reason, duration, and a visible banner
- [ ] [critical] Impersonation cannot change the operator's own identity or bypass step-up controls
- [ ] [recommended] Audit logs record actor, effective subject, action, target, reason, outcome, time, and source
- [ ] [critical] Authorization-service errors fail closed and produce an observable alert

## Before Returning

- [ ] [critical] Tests cover wrong algorithm, wrong issuer/audience, expired token, reuse, fixation, reset replay, and cross-user access
- [ ] [critical] Relevant tests and build/compile commands were run and reported honestly
- [ ] [critical] Runtime assumptions that could not be verified are stated plainly
