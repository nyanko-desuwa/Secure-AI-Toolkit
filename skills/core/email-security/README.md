# Email Security Skill

Guidance for the application-to-mailbox boundary: transactional mail, domain authentication,
templates, provider events, and privacy.

## Purpose

Assistants frequently generate password-reset, verification, invite, and notification mail that
looks complete and is still unsafe. This skill owns the delivery and message-boundary controls that
make those messages reviewable.

## Coverage

| Area | State |
|---|---|
| Transactional mail and security messages | Covered |
| SPF, DKIM, DMARC alignment evidence | Covered at application-config level |
| Provider webhooks, bounces, complaints | Covered |
| HTML/text templates and header safety | Covered |
| Framework/provider syntax | Version-sensitive; named examples only |

Named stacks: Laravel Mail, Django email backends, Spring/Jakarta Mail, ASP.NET/MailKit,
Node/Nodemailer, and common providers such as SES, SendGrid, Mailgun, Resend, and Postmark. Exact
option names must be re-checked against the deployed version.

## Limitations

- DNS and provider dashboards cannot be proven from application source alone.
- Domain authentication reduces spoofing; it does not stop phishing from lookalike domains or a
  compromised mailbox.
- This skill does not replace authentication policy, anti-automation thresholds, or secret rotation.

## Security notes

Vulnerable examples are labelled and paired with fixes. All hosts, domains, keys, and recipients are
synthetic.
