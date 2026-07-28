# Email Security Prompts

## Beginner

```text
Explain how this app sends password-reset email. Say who can change the sender domain, where the
reset link comes from, and what would happen if an attacker controlled the Host header.
```

## Developer

```text
Review the mailer for src/notifications/reset_email.py. Check recipient/header construction, public
origin, template encoding, provider credentials, retries, and logs. Return fixed code and residual
DNS/provider gaps.
```

## Review

```text
Review the email surface against skills/core/email-security/checklist.md. For each finding give
category, file:line, exploitation path, fix, and severity. Skip anything without an exploit path.
```

## Audit

```text
Map every production sender domain to SPF/DKIM/DMARC evidence, provider webhook verification, bounce
handling, and residual risks. Cite standards and mark unverified live DNS/provider configuration.
```

## Anti-patterns

| Prompt | Why it fails |
|---|---|
| “Is email secure?” | Produces generic reassurance |
| “Just enable SPF” | Ignores DKIM/DMARC alignment, links, webhooks, and privacy |
| “Disable TLS verification for SMTP” | Removes a control rather than fixing trust |
