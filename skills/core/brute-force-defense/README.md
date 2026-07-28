# Brute Force Defense Skill

## Purpose

Give one place to review any online guessing surface. Login is only the obvious one. OTP codes,
reset tokens, email verification links, API keys, invite and coupon codes, short URLs, object IDs,
and secret comparisons all have candidate spaces an attacker can search.

This skill owns rate limiting, detection, and response. It does not repeat password hashing from
`advanced/cryptography`, session design from `authentication`, or generic API resource budgets
from `api-security`.

## How It Works

Read [SKILL.md](SKILL.md), classify the attack shape, enumerate every guessable surface, then
choose shared counters that cover account, IP, subnet or ASN, device, and the system globally.
Run [checklist.md](checklist.md) before returning code.

```text
SKILL.md
README.md
checklist.md
best-practices.md
common-mistakes.md
troubleshooting.md
prompts.md
references/
  owasp-top10-asvs.md
  owasp-cheatsheets.md
  nist-800-63b-throttling.md
  cwe-guessing.md
examples/
  README.md
```

The examples are defensive. There are no stuffing scripts, password lists, credential validators,
or automation for trying candidates.

## Standards

| Standard | Version | Use here | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A07 Authentication Failures, A06 Insecure Design, A09 Logging and Alerting; A04/A01 where the weakness is randomness/authorization | 2026-07-28 |
| OWASP ASVS | 5.0.0, released 2025-05-30 | V6 Authentication, V16 Security Logging and Error Handling; V7/V11 as supporting chapters | 2026-07-28 |
| OWASP API Security Top 10 | 2023 | API2 Broken Authentication, API4 Unrestricted Resource Consumption, API6 Sensitive Business Flows | 2026-07-28 |
| NIST Digital Identity Guidelines | SP 800-63B-4 | Section 3.2.2 throttling, 3.1.1.2 password blocklists, 3.1.2-3.1.5 OTP and look-up-secret limits | 2026-07-28 |
| OWASP Cheat Sheet Series | Current web editions; pages expose no version | Credential Stuffing Prevention, Authentication | 2026-07-28 |
| MITRE CWE | Web catalogue | CWE-307, -799, -645, -204, -208, -180, -294, -330, -340, -521, -532, -770, -778, -862 | 2026-07-28 |

ASVS mappings remain at chapter level. Requirement IDs are not carried over from 4.x and are not
invented here.

## Configuration

The skill has no build step or runtime dependency. The code patterns assume a shared Redis
instance for counters. A production project still has to choose and document:

- Limits for account, IP, subnet/ASN, device, and global failures over both burst and long windows
- The identifier normalisation function used everywhere, including aliases and Unicode policy
- The behaviour while the limiter store is unavailable, and the availability budget that permits
  authentication to be denied
- The friction ladder: delay, CAPTCHA, verified-email step, extreme-count hard lock
- OTP attempts per challenge, code lifetime, resend budget, and whether a new code invalidates the
  old code without resetting attempts
- Alert baselines per service, region, tenant, and hour of week
- The proxy trust boundary. Never take the leftmost `X-Forwarded-For` from an untrusted client

Start thresholds from measured legitimate traffic, not numbers copied from an example. NIST's 100
consecutive attempts is an upper bound, not a recommended threshold.

## Example Usage

```text
Review every login-capable path in this repository for guessing resistance. Include web, mobile,
legacy, basic auth, SSO callback, and password grant. For each finding give file:line, attack
shape, counter dimension, bypass, A07/A06 mapping, ASVS V6, CWE, and fixed code.
```

```text
Threat-model this six-digit OTP flow. Assume the attacker knows the account identifier and rotates
addresses. Check attempts per challenge, atomic consumption, resend limits, whether resend resets
the counter, and TOTP replay within one time step.
```

```text
Review our GraphQL and JSON-RPC request limits. Prove whether one request with 100 operations
counts as one attempt or 100. Give a regression test that fails before the fix and passes after.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown cannot prove which gateway config is deployed, whether every pod shares Redis, or
  whether the application trusts only known proxies. Exercise the live path.
- Device fingerprints are client-controlled and spoofable. Treat them as a risk signal, never an
  identity or a hard-block key.
- IP and ASN reputation misclassify VPNs, mobile carriers, corporate NAT, privacy relays, and
  accessibility services. They adjust friction; they do not prove an attacker.
- A CAPTCHA raises cost. Solver services and automation defeat it. It is not a wall.
- Fail-closed limiting makes authentication unavailable when the counter store is unavailable.
  That is deliberate, but the dependency needs redundancy, timeouts, and an incident runbook.
- UUIDv4 raises enumeration cost. It does not authorize an object and does not repair A01.
- Rate limiting does nothing against offline cracking after a hash leak. That is KDF work in
  `advanced/cryptography`.
- Threshold examples are starting points for an alert discussion, not universal safe values.
  Fixed thresholds without baselines produce noise or blind spots.
- Perfect OTP attempt limits do not stop phishing proxies that relay a valid code in real time.
  Use WebAuthn for phishing resistance.
- Email verification and password reset are only as strong as the email and support recovery
  process behind them.

## Security Notes

Every vulnerable block is labelled `Vulnerable:` and paired with a fixed version. Do not copy a
labelled-vulnerable block. Examples use placeholder hosts and Redis keys only.

Log event metadata, not candidates. Never log attempted passwords, OTPs, recovery codes, reset
or verification tokens, API keys, HMAC values, or even a prefix/partial token. A partial token
still reduces the remaining guess space.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- NIST SP 800-63B-4 — <https://pages.nist.gov/800-63-4/sp800-63b.html>
- OWASP Credential Stuffing Prevention Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html>
- OWASP Authentication Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- MITRE CWE — <https://cwe.mitre.org/data/index.html>
