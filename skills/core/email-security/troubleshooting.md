# Email Security Troubleshooting

## A provider does not sign raw body events

Prefer a provider that documents raw-body signatures. If only selected fields are signed, verify
exactly those fields, reject unknown fields, and document residual replay risk.

## Marketing and transactional domains share identity

Separate them. A marketing-domain compromise or weak DMARC policy should not weaken password-reset
and verification mail.

## Forwarding breaks SPF

Use DKIM alignment and DMARC policy appropriate to the domain. Do not disable authentication checks
to make a mailing list "work".

## Local development needs fake mail

Use a local capture tool or sandbox provider with non-production secrets and non-production domains.
Never point production DNS records or DKIM keys at a developer mailbox.
