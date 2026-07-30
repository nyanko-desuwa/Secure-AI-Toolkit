# Brute Force Defense Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable" needs a
one-line reason. Check the deployed gateway and every alternate path before marking an
application handler safe.

## Attack shape (A06:2025 · ASVS V6 · CWE-307, CWE-799)

- [ ] [recommended] Classify the abuse as brute force, credential stuffing, spraying, reverse brute force, or offline cracking
- [ ] [recommended] State the attacker's starting knowledge: account identifier, leaked pair, token prefix, or hash database
- [ ] [critical] List every endpoint that verifies the same credential, including mobile, legacy, SSO, basic auth, and password grant
- [ ] [critical] List every non-password guessable value: OTP, reset and verification token, recovery code, API key, invite/coupon code, short URL, identifier
- [ ] [recommended] For each value, state candidate-space size, lifetime, attempts allowed, and the consequence of a hit
- [ ] [recommended] Offline cracking is routed to KDF review, not presented as solvable by an online limiter

## Limiter dimensions (A07/A06:2025 · ASVS V6 · CWE-307, CWE-645)

- [ ] [critical] New and changed passwords are checked as whole values against a breached/common-password corpus (CWE-521)

- [ ] [critical] Counter includes normalised account identifier, not just source IP
- [ ] [recommended] Counter includes source IP and a broader network signal such as trusted subnet or ASN
- [ ] [recommended] Device fingerprint is a soft signal, not identity and not the only counter
- [ ] [critical] Global failure-rate control catches one attempt across many accounts
- [ ] [recommended] Burst and long-window limits both exist; a low-and-slow attack fits neither gap
- [ ] [recommended] Thresholds come from measured legitimate traffic and have an owner/review date
- [ ] [recommended] Hard account lockout is reserved for extreme counts and has self-service recovery
- [ ] [recommended] Shared NAT and mobile-carrier users are not permanently blocked by one actor

## Counter correctness (A07/A10:2025 · ASVS V6/V16 · CWE-307, CWE-770)

- [ ] [recommended] All application instances use the same counter store
- [ ] [critical] Increment and first expiry are atomic; there is no GET-then-SET race
- [ ] [critical] Counter failure denies or adds safe friction; it never becomes unlimited attempts
- [ ] [recommended] Counter-store timeout is short and the failure is alerted; Redis/Valkey ACL, TLS, persistence, eviction, and service configuration are checked with `redis-security`
- [ ] [critical] Identifier key uses the same Unicode, whitespace, case, and alias normalisation as account lookup
- [ ] [critical] Proxy-derived IP uses a trusted-proxy configuration, not arbitrary `X-Forwarded-For`
- [ ] [critical] Every credential check increments the attempt counter, including malformed and batch-carried attempts
- [ ] [recommended] A successful authentication resets only the intended account/authenticator counters
- [ ] [recommended] Regression tests cover concurrency, several app instances, Redis failure, and key expiry

## Graduated friction (A06/A07:2025 · ASVS V6 · CWE-645)

- [ ] [recommended] Response progresses from delay to CAPTCHA to verified recovery step before hard lock
- [ ] [recommended] Delay has jitter and a maximum; it does not pin server workers or sockets
- [ ] [recommended] CAPTCHA is server-verified, single-use, short-lived, and risk-triggered
- [ ] [recommended] CAPTCHA is documented as a cost multiplier, not the only control
- [ ] [recommended] Legitimate user has a documented path back in that does not expose whether the account exists

## OTP, MFA, and recovery (A07:2025 · ASVS V6 · CWE-307, CWE-799)

- [ ] [critical] OTP attempts are capped per challenge/account; cap invalidates the challenge
- [ ] [critical] OTP consumption and replay marking are atomic
- [ ] [recommended] Resend has its own rate and total cap
- [ ] [recommended] Resend does not reset the failed-attempt counter
- [ ] [critical] Issuing a replacement invalidates older out-of-band codes, with race behaviour tested
- [ ] [critical] TOTP time step can be accepted only once per account; accepted counter/time-step is persisted
- [ ] [critical] Recovery codes are single-use, stored as hashes, and rate limited
- [ ] [recommended] A correct password followed by failed MFA raises a higher-confidence compromise signal

## Tokens, keys, codes, and IDs (A04/A01/A06:2025 · ASVS V11/V6/V8 · CWE-330, CWE-340, CWE-799)

- [ ] [critical] Reset and email verification tokens come from a CSPRNG with enough entropy
- [ ] [critical] Tokens are stored hashed where database disclosure would otherwise make them usable
- [ ] [critical] Tokens are single-use, expiring, scoped to purpose and account, and atomically consumed
- [ ] [recommended] API key, invite, coupon, and short-link validation has an attempt budget
- [ ] [critical] Secret and HMAC comparison uses a constant-time helper (CWE-208)
- [ ] [critical] Sequential IDs are treated as enumerable and every object access still authorizes server-side
- [ ] [critical] Switching an ID to UUIDv4 is not reported as an authorization fix

## Batch and alternate paths (API2/API4/API6:2023 · ASVS V4/V6 · CWE-307, CWE-770)

- [ ] [critical] GraphQL aliases, arrays, fragments, and batching cannot carry more attempts than counted
- [ ] [critical] JSON-RPC/gRPC/batch operations are limited by operation or candidate, not envelope request
- [ ] [recommended] Gateway body/operation limits backstop application counters
- [ ] [critical] Web, mobile, legacy, internal, and partner routes share one limiter policy and store
- [ ] [critical] Password reset, registration, token refresh, and support impersonation are reviewed as login-adjacent paths

## Detection and logging (A09:2025 · ASVS V16 · CWE-778)

- [ ] [recommended] Events include outcome, normalised account hash, source IP/network, device risk, route, limiter action, and timestamp
- [ ] [critical] Attempted passwords, OTPs, tokens, API keys, HMACs, and partial values never enter logs
- [ ] [recommended] Alert sees elevated global failure rate with low failures per account
- [ ] [recommended] Alert sees many distinct accounts per source/network and many sources per account
- [ ] [recommended] Alert sees unusual success-after-failure ratio, correct-password/failed-MFA, and limiter-store failure
- [ ] [recommended] Fixed thresholds are paired with baselines by hour, region, tenant, or channel
- [ ] [recommended] New-device and impossible-travel signals run after a successful authentication
- [ ] [recommended] Alert has an owner, runbook, suppression policy, and tested route

## Response (A07/A09:2025 · ASVS V7/V16)

- [ ] [critical] Confirmed or likely successful guessing revokes active sessions and refresh-token families
- [ ] [critical] Password or affected secret is reset; exposed API keys and recovery codes rotate
- [ ] [recommended] Review covers email, MFA enrolment, recovery method, API key, forwarding rule, payout, and role changes
- [ ] [recommended] User notification uses a channel not changed by the attacker where possible
- [ ] [recommended] Evidence is preserved and `advanced/incident-response` runbook is invoked

## Before Returning

- [ ] [recommended] Every finding names category, ASVS chapter, CWE, location, precondition, exploitation path, and fix
- [ ] [critical] Relevant limiter tests or config validation ran and output is reported honestly
- [ ] [recommended] Availability tradeoff of failing closed is stated
- [ ] [critical] Any gateway, Redis, IdP, or runtime behaviour not inspected is marked unverified
- [ ] [recommended] No offensive guessing automation, credential list, or candidate-testing tool was produced
