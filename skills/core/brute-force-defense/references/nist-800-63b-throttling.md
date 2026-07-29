# NIST SP 800-63B-4 - throttling, blocklists, and OTP limits

Digital Identity Guidelines: Authentication and Authenticator Management, Revision 4.
Only the sections relevant to guessing attacks are summarised here. For password length,
AAL definitions, and PSTN restrictions see `core/authentication/references/nist-800-63b.md`.

Source: <https://pages.nist.gov/800-63-4/sp800-63b.html>
Publication record: <https://csrc.nist.gov/pubs/sp/800/63/b/4/final>
Verified: 2026-07-28, section text fetched from the NIST HTML edition.

## Section 3.2.2 - Rate limiting (throttling)

The normative core: a verifier limits consecutive failed authentication attempts using a
specific authenticator on a single subscriber account to no more than 100, by disabling that
authenticator. If several authenticators are implicated in the excessive attempts, both are
disabled. A disabled authenticator must be re-bound to the account under Section 4.1 before it
works again.

100 is explicitly an upper bound. Agencies may impose lower limits. The number was chosen to
balance guess probability against recovery burden, not because 100 guesses are safe.

Mitigations the section lists so the limit does not lock out legitimate users:

- A bot detection and mitigation challenge before authentication is attempted
- Escalating waits after failures, with 30 seconds up to an hour given as the example range
- Risk-based or adaptive authentication using signals such as IP address, geolocation, request
  timing, and browser metadata

On a successful authentication the verifier should disregard previous failed attempts and reset
the retry count for the authenticators used - with the caveat that the reset authenticator's
maximum AAL cannot exceed the AAL of the session that performed the reset. Otherwise account
recovery under Section 4.2 applies.

Read the shape of this requirement carefully. It is per account, per authenticator. It says
nothing about one attempt each against a million accounts from a rotating address pool, which
is what credential stuffing and spraying actually look like. Treat it as a floor and add
per-IP, per-ASN, and global-failure-rate controls above it.

## Section 3.1.1.2 - Password blocklist

Verifiers compare a prospective password against a blocklist of known commonly used, expected,
or compromised passwords, at establishment and at change. The entire password is compared, not
substrings or contained words. Named sources include breach corpuses, dictionary words, and
context-specific terms such as the service name or the username.

On rejection the subscriber must choose something else, and the verifier states the reason for
rejection and offers guidance toward a strong password.

Sizing is deliberately modest: the blocklist should be large enough to block passwords likely
to be guessed within the attempt limit, and the document notes that excessively large
blocklists give little incremental benefit given throttling. Throttling and the blocklist are
sized against each other.

There is no periodic forced rotation, but a change is forced on evidence that the authenticator
has been compromised.

## Out-of-band and OTP attempt limits

These are the numbers that matter for OTP guessing, and they are the ones most often absent
from application code.

| Authenticator | Section | Requirement |
|---|---|---|
| Out-of-band (SMS, push) | 3.1.3.2 | Code at least six decimal digits from an approved RBG. Rate limit per 3.2.2 required when the secret is shorter than 64 bits. Authentication invalid unless completed within 10 minutes. Each secret valid once during the validity period. Generating a new secret does not reset the failed attempt count. A reasonable limit on the rate or total number of push notifications since the last success |
| Single-factor OTP | 3.1.4.2 | Rate limiting mandatory when the authenticator output is under 64 bits. Output may be truncated to as few as six decimal digits. Seed key at least 112-bit security strength. Clock-based nonce changes at least every two minutes. Each OTP accepted only once while valid |
| Multi-factor OTP | 3.1.5.2 | The verifier implements a rate-limiting mechanism, unconditionally. No 64-bit carve-out |
| Look-up secrets (recovery codes) | 3.1.2.1, 3.1.2.2 | At least six decimal digits or equivalent. Below 112-bit strength they are salted and hashed with a password hashing scheme, salt at least 32 bits, and rate limited. Each secret single-use |
| Biometric | 3.2.3.3 | No more than five consecutive failures, or 10 with conformant presentation attack detection, then a delay of at least 30 seconds before each subsequent attempt. Overall cap 50, or 100 with PAD |

Two details from 3.1.3.2 are the ones that get skipped in practice:

- Reissuing the code does not reset the failure counter. Without this, an attacker exhausts the
  cap, requests a fresh code, and continues indefinitely.
- Single use within the validity period. Accepting the same code twice inside the same time
  step turns an observed code into a replayable one.

## Section 3.2.5 - Phishing resistance

Relevant here for one reason: none of the manually entered authenticator types above are
phishing-resistant, because manual entry does not bind the authenticator output to the session
being authenticated. Perfect OTP attempt limiting does not stop a real-time phishing proxy
relaying the code. WebAuthn qualifies through verifier name binding.

## What this document does not cover

It is US federal guidance for credential service providers. It does not address rate limiting
of API keys, coupon codes, object identifiers, GraphQL batch abuse, or HMAC timing leaks. For
those, work from the CWE entries in [cwe-guessing.md](cwe-guessing.md) and the OWASP cheat
sheets in [owasp-cheatsheets.md](owasp-cheatsheets.md).
