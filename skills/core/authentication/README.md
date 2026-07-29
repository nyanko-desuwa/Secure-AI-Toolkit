# Authentication Skill

## Purpose

Turn identity and access standards into implementation decisions. This skill covers the full
lifecycle: password verification, login abuse controls, sessions and cookies, JWT, OAuth2/OIDC,
MFA, recovery, impersonation, and authorization.

It is guidance for code review and design. It is not an identity provider, a compliance
certificate, or a substitute for testing the deployed configuration.

## How It Works

Read [SKILL.md](SKILL.md) first. Then pull the file matching the change:

```text
SKILL.md
README.md
checklist.md
best-practices.md
common-mistakes.md
troubleshooting.md
prompts.md
references/
  asvs-auth-chapters.md
  nist-800-63b.md
  oauth-rfc9700.md
  password-storage.md
examples/README.md
```

The workflow is scope, map, apply, verify, report. A finding needs an exploitation path, not
just a scary category. All examples labelled `Vulnerable:` are intentionally unsafe.

## Standards

| Standard | Version | Use here | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A07 Authentication Failures; A01 Broken Access Control | 2026-07-28 |
| OWASP ASVS | 5.0.0 | V6 Authentication, V7 Session Management, V8 Authorization, V9 Self-contained Tokens, V10 OAuth and OIDC | 2026-07-28 |
| NIST Digital Identity Guidelines | SP 800-63B-4 | Passwords, throttling, authenticator assurance, phishing resistance, PSTN and recovery | 2026-07-28 |
| OAuth 2.0 Security BCP | RFC 9700 / BCP 240 | PKCE, grant choice, redirect URI, refresh-token replay | 2026-07-28 |

CWE mappings are attached where a weakness has a direct CWE: CWE-256 (plaintext password
storage), CWE-307 (improper restriction of excessive authentication attempts), CWE-384
(session fixation), CWE-613 (insufficient session expiration), CWE-347 (improper signature
verification), CWE-352 (CSRF), CWE-640 (password reset), and CWE-862 (missing authorization).

OWASP Top 10 2025 is not the 2021 list with a date changed. A03 and A10 are new, and
Injection is A05. This skill only uses the relevant A07 and A01 mappings.

## Configuration

No build step or runtime dependency. The skill reads source code and configuration. To apply it,
keep this repository available or copy `skills/core/authentication/` into `~/.claude/skills/`.
The frontmatter intentionally permits read, edit, search, directory listing, and web lookup,
not arbitrary shell commands.

Project-specific decisions still need values. Set and document:

- Argon2id cost after measuring on production-class hardware
- idle and absolute session timeout by risk tier
- rate limits by account, IP, ASN, device, and global failure rate
- access-token and refresh-token lifetimes
- step-up triggers and the recovery policy for lost factors
- authorization policy ownership and audit trail

Do not copy a timeout or KDF cost without measuring it.

## Example Usage

```text
Review src/auth/login.ts against OWASP A07:2025 and ASVS V6/V7. Check uniform errors,
credential-stuffing resistance, password hashing, session rotation, cookie flags, and logout.
For each finding give file:line, precondition, exploitation path, CWE, and fixed code.
```

```text
Threat-model this password reset flow. Assume the attacker knows the victim's email and can
make unlimited requests from rotating IPs. Cover enumeration, token entropy, single use,
expiry, session invalidation, logging, and account recovery.
```

```text
Choose RBAC, ABAC, or ReBAC for this multi-tenant document system. Give an auditable policy
shape, deny-by-default enforcement point, and tests for cross-tenant access.
```

## Limitations

- Markdown guidance cannot prove dataflow, runtime cookie flags, reverse-proxy behaviour, or
  identity-provider configuration. Pair it with tests, SAST, and an IdP review.
- NIST SP 800-63B-4 is US digital-identity guidance for credential service providers. It does
  not define authorization, JWT validation, OAuth grant selection, or browser cookie policy.
- OWASP ASVS 5.0 requirement IDs are deliberately not listed here. Chapter-level citations are
  reliable; exact IDs must be checked against the official 5.0 requirement set.
- Argon2id costs are workload-dependent. The values in `references/password-storage.md` are
  OWASP cheat-sheet recommendations, not a guarantee of adequate cost for your hardware.
- Stateless JWTs cannot provide instant revocation without a server-side check. A short expiry
  reduces the window; it does not remove it.
- SMS is restricted rather than universally forbidden by NIST. It remains vulnerable to SIM
  swap, number porting, phishing, and carrier failure. Offer WebAuthn or TOTP instead.
- Password reset and MFA recovery are only as strong as the support and email/phone account
  behind them. A secure token does not make an insecure help-desk process safe.

## Security Notes

The examples and vulnerable blocks contain no real credentials, tokens, hostnames, or personal
data. Never copy a block labelled `Vulnerable:`. Logs must contain event metadata, not
passwords, reset tokens, access tokens, refresh tokens, recovery codes, or full claims.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 - <https://owasp.org/www-project-application-security-verification-standard/>
- NIST SP 800-63B-4 - <https://csrc.nist.gov/pubs/sp/800/63/b/4/final>
- OAuth 2.0 Security BCP, RFC 9700 - <https://www.rfc-editor.org/rfc/rfc9700.html>
- OWASP Password Storage Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- OWASP Session Management Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
