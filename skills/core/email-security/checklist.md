# Email Security Checklist

Mark every item pass, fail, or N/A with evidence. N/A needs a reason.

## Identity and links

- [ ] [critical] Sender domains, From, Reply-To, and Return-Path are configured allowlists, not tenant input.
- [ ] [recommended] SPF, DKIM, and DMARC alignment evidence is recorded for every production sender domain.
- [ ] [critical] Reset, verification, and invite links use configured public origin, never request Host headers.
- [ ] [critical] Tokens are opaque, expiring, single-use, and handled by `authentication`.

## Message construction

- [ ] [critical] Recipient addresses and headers use library fields; CR/LF input is rejected.
- [ ] [critical] HTML templates contextually encode untrusted values; text alternative exists where applicable.
- [ ] [recommended] Messages minimize personal data, tokens, and sensitive URLs.
- [ ] [critical] Attachments route through upload/parser controls before delivery.

## Provider and operations

- [ ] [critical] SMTP/API and DKIM secrets are managed and rotated outside source code.
- [ ] [critical] Provider webhook raw body/signature/freshness/replay behavior is verified with `api-security`.
- [ ] [recommended] Sending, resend, and bounce/complaint paths have bounded retries and idempotent message IDs.
- [ ] [recommended] Logs redact message body, recipients where unnecessary, tokens, URLs with secrets, and credentials.
- [ ] [recommended] Alerts cover sender-domain changes, webhook verification failures, bounce/complaint spikes, and send anomalies.

## Stop conditions

Stop release for a public sender domain without authorized identity controls, a security link based on
untrusted Host input, a provider event that changes state without verification, or credentials in
source/logs.
