# OWASP cheat sheets on guessing attacks

Two cheat sheets carry the practical guidance. Both were fetched and read on 2026-07-28. Neither
publishes a version number or a last-reviewed date in its content, so cite them by name and URL,
not by version.

- Credential Stuffing Prevention —
  <https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html>
- Authentication —
  <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## The attack split, in OWASP's words

The Credential Stuffing sheet separates three attacks and notes the defences largely overlap:

| Attack | Sheet's definition |
|---|---|
| Brute force | Testing multiple passwords from a dictionary or other source against a single account |
| Credential stuffing | Testing username/password pairs obtained from the breach of another site |
| Password spraying | Testing a single weak password against a large number of different accounts |

## MFA is the headline control

Both sheets call MFA by far the best defence against the majority of password-related attacks,
citing Microsoft analysis that it would have blocked 99.9% of account compromises. The Credential
Stuffing sheet argues the feasibility objection is now weak because browsers and phones support
FIDO2 passkeys.

Where mandatory MFA is not practical, it can be triggered conditionally on unfamiliar device or
IP, unusual or untrusted country, denylisted or VPN/proxy addresses, an IP touching many
accounts, or traffic that looks scripted. The same signals gate step-up prompts before high-risk
actions. Applying MFA unevenly by role — mandatory for administrators only — is explicitly
offered as a partial position.

Secondary passwords, PINs, and security questions are explicitly not MFA. Both factors are
knowledge-based.

## CAPTCHA is qualified, not recommended outright

The Credential Stuffing sheet states CAPTCHAs are not perfect and that tooling or solver services
defeat them with a reasonably high success rate. The Authentication sheet calls CAPTCHA
supplementary rather than preventative, and suggests triggering it only after a few failed
attempts.

Useful detail from the stuffing sheet: track solve rates in both directions. A falling rate means
real users are suffering; an unusually high rate identifies solver bots.

## IP blocking and rate limiting are explicitly not primary controls

The stuffing sheet says blocking may stop unsophisticated attacks but is easy to circumvent, and
prefers a graduated response. Specific points worth carrying into code:

- Thresholds must cover both burst and long-window patterns, including low-and-slow traffic
  spread across many addresses
- Classify addresses: residential versus hosting provider, and adjust thresholds accordingly.
  Forcing CAPTCHA on all hosting-provider traffic is given as a concrete tactic
- Blocks should be temporary with a documented path out
- Proxy networks in commodity attack kits defeat denylists and per-IP limits by keeping
  per-address volume low
- Storing per-account IP history lets you lock and warn an account whose recent address later
  appears on a block list

## Account lockout, from the Authentication sheet

Login throttling is the general mechanism; account lockout is one implementation. The sheet's
design points:

- Tie the failure counter to the account, not the source IP, so an attacker cannot spread
  attempts across addresses
- Tune three parameters: lockout threshold, observation window, lockout duration
- Prefer exponential backoff over a fixed duration, starting around one second and doubling per
  failure
- Guard against lockout being weaponised for denial of service. One suggested mitigation: let the
  forgotten-password flow keep working while the account is locked

Note the tension with the stuffing sheet, which says per-IP limits are weak. Neither sheet says
one dimension is sufficient. Read them together as an argument for multiple counters.

## Enumeration and timing

The Authentication sheet requires the same generic message from login, password reset, recovery,
and registration, whether the credential was wrong, the account is missing, or the account is
locked. It names the risk as a discrepancy factor.

Timing is treated as an enumeration channel: the sheet contrasts a quick-exit implementation that
returns early for a missing user against one that always hashes, so response time stays roughly
constant. It also warns that differing HTTP status codes (200 versus 403) leak account validity
even behind a generic page body.

## Notification guidance

From the stuffing sheet, and the rule most often implemented backwards:

- A failed password attempt generally does not merit a message
- A correct password followed by a failed MFA check does. That means the password is known and
  should be changed
- Repeated reset requests from varied devices or addresses may justify freezing the account
  pending verification
- Users should see recent login details and be able to review and kill active sessions
- Notify selectively to avoid alert fatigue, and remember the user's email may itself be breached

## Other measures the stuffing sheet lists

Breached-password screening against a corpus such as Pwned Passwords, self-hosted or via API.
Unpredictable usernames, because stuffing depends on username reuse as much as password reuse.
Multi-step login, which breaks single-step tooling and doubles attacker requests, provided it does
not leak enumeration. Requiring JavaScript or blocking headless browsers, with the accessibility
cost named outright. Degradation tactics: escalating JavaScript complexity, proof-of-work,
delayed responses, randomised errors.

The sheet's closing position is defence in depth with metrics: assume individual controls fail,
especially client-side ones, and instrument each defence with detected and mitigated volume.

## Device and connection fingerprinting

Passive HTTP signals plus JavaScript-derived data build a device fingerprint. The sheet's caveat
is the important part: everything comes from the client and can be spoofed, trivially for the
User-Agent. Connection-level fingerprinting (JA3, HTTP/2 fingerprinting, header ordering) is
presented as more reliable because it keys on how the connection is made, and contradictions
between layers are a strong signal — a mobile user agent paired with a scripted client's
connection signature.

Mismatches should prompt extra authentication, not an outright block. Users legitimately own
several devices.
