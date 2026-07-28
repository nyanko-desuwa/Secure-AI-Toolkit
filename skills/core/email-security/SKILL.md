---
name: email-security
description: 'Secure transactional email and provider delivery — SPF/DKIM/DMARC, recipients/headers, reset/verification delivery, templates, webhooks, bounces, and privacy. Triggers: "email security", "SMTP", "DKIM", "SPF", "DMARC", "password reset email", "magic link", "mail webhook", "bảo mật email", "gửi email".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Email Security

Email is a delivery boundary, not a free-form string. A wrong Host, header, sender identity, or
provider event turns recovery and notification into account takeover, spoofing, or abuse.

## When to Use

- Designing or reviewing transactional email: verification, password reset, magic links, invites
- Configuring SMTP, SES, SendGrid, Mailgun, Resend, Postmark, or similar provider APIs
- Publishing or reviewing SPF, DKIM, DMARC, or sender-domain alignment
- Handling provider webhooks, bounces, complaints, or delivery retries
- Building HTML/text templates that insert user or tenant data

## When NOT to Use

| Concern | Route to |
|---|---|
| Token entropy, expiry, single use, session invalidation after recovery | `authentication` |
| Guessing thresholds, lockout, anti-automation for resend/login | `brute-force-defense` |
| Credential/secret storage and rotation | `secrets-management` |
| Provider webhook authorization and API surface | `api-security` |
| Host/proxy trust for absolute URLs | `http-edge-security` |
| Outbound HTTP client transport to a provider | `http-client-security` |
| Audit retention and SIEM design | `logging-audit` |
| Attachment malware/parser handling | `file-upload-security`, `deserialization-security` |

## Ownership Boundary

**Owns:** Application ↔ SMTP/provider API ↔ recipient mailbox delivery, sender identity, message
safety, provider events, bounce handling, and email privacy evidence.

**Does not own:**

| Concern | Route to |
|---|---|
| Password-reset eligibility, token lifecycle, and session issuance | `authentication` |
| Resend/login guessing policy and lockout thresholds | `brute-force-defense` |
| SMTP/API credential and DKIM private-key lifecycle | `secrets-management` |
| Provider webhook request verification and endpoint authorization | `api-security` |
| Outbound HTTP client construction and TLS verification | `http-client-security` |

## Standards This Skill Maps To

| Standard | Use it for | Version here |
|---|---|---|
| OWASP Top 10 | Access control, misconfiguration, integrity, logging, and failure handling | 2025 |
| OWASP ASVS | Authentication/session delivery evidence, configuration, communication, logging | 5.0.0 |
| SPF / DKIM / DMARC RFCs | Domain authentication and alignment | RFC 7208, 6376, 7489 |
| SMTP / message format | Envelope and header safety | RFC 5321, 5322 |

Source pins live in [references/](references/).

## Workflow

### 1. Inventory the mail surface

List every send path, template, provider, domain, webhook, bounce/complaint handler, and queue or
outbox path that can produce a security-sensitive message.

### 2. Fix identity and destination before content

- Sender domains and From/Reply-To/Return-Path values are allowlisted and tenant-bound.
- Recipients are structured addresses, not concatenated headers.
- Absolute security links come from configured public origin, never request Host headers.

### 3. Protect the message and the event path

- Tokens are opaque, expiring, single-use, and owned by `authentication`.
- Templates use contextual encoding; HTML is constrained.
- Provider webhooks verify raw body, timestamp, and replay; processing is idempotent.
- Retries have a message identity so recovery mail is not duplicated blindly.

### 4. Protect transit, secrets, and telemetry

- SMTP/API credentials and DKIM keys are secret-managed.
- Transport uses TLS with verification where the client library supports it.
- Logs never store full message bodies, tokens, or provider secrets.

### 5. Verify and report

Run [checklist.md](checklist.md). For each finding: surface, exploit path, CWE/standard, fix, and
what live DNS/provider configuration remains unverified.

## Severity

- **Critical** — attacker can take over accounts via poisoned links, forge recovery mail, or send as
  an unauthorized domain with a path to user action
- **High** — header injection, unsigned provider events that change account state, unrestricted
  resend that enables takeover or mass abuse
- **Medium** — incomplete SPF/DKIM/DMARC alignment, weak bounce handling, privacy-leaking templates
- **Low** — defence-in-depth gaps with no demonstrated path

## Related Skills

- `authentication` — token and session policy behind security mail
- `brute-force-defense` — resend and guessing policy
- `api-security` — provider webhook endpoints
- `http-client-security` — provider API transport
- `http-edge-security` — Host and absolute URL trust
- `secrets-management`, `logging-audit`

## Supporting Files

- [README.md](README.md)
- [checklist.md](checklist.md)
- [best-practices.md](best-practices.md)
- [common-mistakes.md](common-mistakes.md)
- [troubleshooting.md](troubleshooting.md)
- [prompts.md](prompts.md)
- [references/](references/)
- [examples/README.md](examples/README.md)
