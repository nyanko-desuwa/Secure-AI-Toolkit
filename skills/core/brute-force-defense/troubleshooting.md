# Troubleshooting

What to do when the secure design conflicts with availability, product requirements, or
infrastructure reality.

## Redis is down and product will not accept failed login

The secure default is fail closed: 503, alert, and keep existing sessions working where policy
permits (`A10/A07:2025` · ASVS V16/V6 · CWE-307). An unavailable limiter cannot become unlimited
attempts.

If the business explicitly chooses availability, do not silently catch and continue. Record the
risk and choose a bounded degraded mode:

1. Require an already enrolled phishing-resistant factor before password verification.
2. Route to a small, strongly capped gateway emergency budget shared across instances.
3. Deny new devices and permit only recently trusted devices with step-up.

A per-process fallback is not equivalent. It multiplies the budget by pod count, resets on
restart, and is hard to observe. Put redundancy, short timeouts, and an incident runbook around
the limiter store instead.

## Per-account limits lock out real users

That is the expected failure of binary lockout: an unauthenticated attacker controls account
availability (`A06/A07:2025` · ASVS V6 · CWE-645).

Replace hard lock with increasing asynchronous delay, then risk-triggered CAPTCHA, then a
verified-email or WebAuthn step. Hard lock only at an extreme count with self-service recovery.
Keep responses uniform so the locked state does not confirm account existence. Measure recovery
abandonment as well as attacks blocked.

Do not raise the hard-lock threshold until complaints stop. That simply gives attackers more
guesses and preserves the same DoS lever.

## Shared NATs keep tripping the IP budget

An IP is a routing hint, not a person. Corporate proxies, mobile carriers, schools, privacy
relays, and accessibility services aggregate legitimate users.

Use the IP limit as one dimension and soften its action: delay/CAPTCHA rather than permanent
block. Combine it with account and device risk. Classify hosting-provider and residential ranges,
baseline each network class, and expire blocks. Do not allowlist a whole carrier ASN; attackers
rent residential/mobile exits too.

## There is no reliable device fingerprint

There never is. Browser fingerprint fields are client-controlled and privacy controls make them
unstable. Connection fingerprints also change across proxies, browser updates, and networks.

Use device as a scored signal only. A mismatch triggers step-up, not denial. A match never grants
access or resets the account budget. If privacy policy prohibits fingerprinting, omit it and
strengthen account, network, MFA, and aggregate detection. State the reduced signal, do not invent
a persistent browser identifier.

## The proxy chain makes the client IP unclear

Do not parse the leftmost `X-Forwarded-For` yourself. Configure the application with the exact
trusted proxy count/ranges, and have the edge overwrite rather than append untrusted forwarding
headers. Test with a client-supplied `X-Forwarded-For` and verify it cannot choose the limiter key.

If you cannot prove the chain, label IP-based limiting unverified and lean on account/global
limits until infrastructure owns the fix. Blocking on an attacker-selected key is worse than no
claim.

## GraphQL tooling depends on aliases and batching

Do not disable the protocol feature without measuring who breaks. Put two controls in place
instead (`A06:2025` · API4:2023 · CWE-770): a parse-time operation/alias/depth/body budget to
bound work, and a per-resolver credential-attempt counter to bind candidates. Trusted server-to-
server clients can get an authenticated operation budget; unauthenticated login never gets a
batch exemption.

Persisted queries reduce arbitrary document shape but do not solve repeated calls to an approved
login operation. Count the operation that performs verification.

## A six-digit OTP must remain for compatibility

Six digits is allowed by NIST SP 800-63B-4, but it is a small search space and requires strict
rate limiting. Cap attempts per account/challenge, invalidate on the cap, consume atomically, and
rate limit resend without resetting failures. Persist the accepted TOTP time step to prevent
replay.

A longer code increases space but usually harms manual-entry success. It does not remove the need
for a cap, and no OTP length makes manual entry phishing-resistant. Offer WebAuthn where phishing
resistance matters.

## The identity provider owns throttling and exposes no configuration

"The IdP handles it" is unverified until you inspect its documentation, tenant policy, and the
live path. Test a non-production account up to a safe agreed threshold and observe delay,
challenge, reset, and logs. Check every protocol separately: browser OIDC, resource-owner password
grant, device flow, legacy federation, and help-desk verification may not share controls.

Do not run an uncontrolled guessing test against production. Coordinate the test, use synthetic
accounts, stop before lockout, and verify from telemetry rather than looking for valid credentials.

If the IdP cannot expose or prove its policy, keep gateway/global anomaly detection and record the
per-account control as a supplier limitation.

## The gateway already rate limits requests

Confirm what it counts. A per-IP HTTP request limit does not see canonical account identity,
GraphQL operations inside a request, or one attempt across many accounts. Read the effective
gateway configuration and test body batching.

Keep the gateway control as a burst/resource backstop and the application control at the
credential-verification point. If both return 429, align retry metadata and telemetry so users do
not see contradictory windows.

## Alerts are noisy during releases and outages

Authentication dependency failures look like a spray: broad account failures in minutes. Do not
silence the alert globally. Add a separate dependency-health signal and annotate deploy windows;
route the event differently when failure reason is internal, while retaining the evidence.

Pair fixed thresholds with same-hour/weekday baseline, success ratio, and distinct-account/source
cardinality. Suppression must have an expiry and owner. An outage can also hide a real attack, so
keep raw events searchable.

## Product wants a specific "account locked" message

That confirms a valid account and its state (`A07:2025` · ASVS V6/V16 · CWE-204). Keep the public
login response, HTTP status, and approximate timing uniform: `invalid_credentials` or a generic
`try_later`. Explain the recovery action out of band after the user proves control of the email or
an enrolled factor.

If product knowingly accepts enumeration, document it with throttling and monitoring as
compensating controls. Do not claim the risk is closed.

## UUID migration is proposed as the IDOR fix

A UUIDv4 makes blind enumeration expensive; it does not decide who may read an object. Keep the
migration if lower discoverability is useful, but scope data queries by actor/tenant and return the
same not-found response for absent and unauthorized objects (`A01:2025` · ASVS V8).

If authorization cannot be added because links are intentionally bearer capabilities, say that
plainly. Then the identifier is a secret: use CSPRNG entropy, avoid logs/referrers, support
revocation and expiry, and rate limit validation. That is a different design from a normal object
ID.

## Constant-time comparison helper rejects different lengths

Node's `crypto.timingSafeEqual` throws when buffers differ in length. Validate encoding and fixed
expected length first, then compare equal-length decoded values. Return the same public failure for
bad length, bad encoding, and mismatch. Do not pad attacker input in a way that creates ambiguous
encodings.

Length validation may itself be visible. That is acceptable when the protocol already fixes the
digest length; it reveals format, not a secret prefix. Never add random sleeps as a substitute for
a constant-time helper.

## A checklist item does not apply

Write the reason. "No per-account counter: this endpoint redeems tenant-wide coupon codes, so it
uses tenant + source + global budgets" is complete. An unexplained skip is indistinguishable from
an oversight.

## Two standards appear to disagree

NIST SP 800-63B-4 sets an upper bound per account/authenticator. OWASP adds practical controls for
credential stuffing, spraying, devices, and networks. They cover different attack shapes. Apply
the more specific rule, keep NIST's bound, and add aggregate dimensions.

Use Top 10 for reporting, ASVS for chapter-level verification, CWE for the weakness. Do not stretch
NIST authentication guidance to coupon codes or object identifiers.
