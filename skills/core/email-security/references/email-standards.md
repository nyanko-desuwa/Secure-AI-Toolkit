# Email Transport and Domain Authentication

> RFC references checked 2026-07-29 against the RFC Editor.

| Source | Used for |
|---|---|
| RFC 5321 — SMTP | Envelope, submission/relay concepts, and transport boundary |
| RFC 5322 — Internet Message Format | Header/message syntax and why concatenating headers is unsafe |
| RFC 7208 — SPF | Sender policy framework limits and DNS evidence |
| RFC 6376 — DKIM | Domain-signed message integrity/authentication concepts |
| RFC 7489 — DMARC | Identifier alignment, policy, and reporting concepts |

SPF, DKIM, and DMARC reduce spoofing risk. They do not prove a recipient is legitimate, make a
recovery token safe, or prevent phishing from another authorized-looking domain.

Sources:

- <https://www.rfc-editor.org/rfc/rfc5321>
- <https://www.rfc-editor.org/rfc/rfc5322>
- <https://www.rfc-editor.org/rfc/rfc7208>
- <https://www.rfc-editor.org/rfc/rfc6376>
- <https://www.rfc-editor.org/rfc/rfc7489>
