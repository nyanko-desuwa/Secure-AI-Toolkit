# Brute Force Defense Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable" needs a
one-line reason. Check the deployed gateway and every alternate path before marking an
application handler safe.

## Attack shape (A06:2025 · ASVS V6 · CWE-307, CWE-799)

- [ ] Classify the abuse as brute force, credential stuffing, spraying, reverse brute force, or offline cracking
- [ ] State the attacker's starting knowledge: account identifier, leaked pair, token prefix, or hash database
- [ ] List every endpoint that verifies the same credential, including mobile, legacy, SSO, basic auth, and password grant
- [ ] List every non-password guessable value: OTP, reset and verification token, recovery code, API key, invite/coupon code, short URL, identifier
- [ ] For each value, state candidate-space size, lifetime, attempts allowed, and the consequence of a hit
- [ ] Offline cracking is routed to KDF review, not presented as solvable by an online limiter

## Limiter dimensions (A07/A06:2025 · ASVS V6 · CWE-307, CWE-645)

- [ ] New and changed passwords are checked as whole values against a breached/common-password corpus (CWE-521)

- [ ] Counter includes normalised account identifier, not just source IP
- [ ] Counter includes source IP and a broader network signal such as trusted subnet or ASN
- [ ] Device fingerprint is a soft signal, not identity and not the only counter
- [ ] Global failure-rate control catches one attempt across many accounts
- [ ] Burst and long-window limits both exist; a low-and-slow attack fits neither gap
- [ ] Thresholds come from measured legitimate traffic and have an owner/review date
- [ ] Hard account lockout is reserved for extreme counts and has self-service recovery
- [ ] Shared NAT and mobile-carrier users are not permanently blocked by one actor

## Counter correctness (A07/A10:2025 · ASVS V6/V16 · CWE-307, CWE-770)

- [ ] All application instances use the same counter store
- [ ] Increment and first expiry are atomic; there is no GET-then-SET race
- [ ] Counter failure denies or adds safe friction; it never becomes unlimited attempts
- [ ] Counter-store timeout is short and the failure is alerted
- [ ] Identifier key uses the same Unicode, whitespace, case, and alias normalisation as account lookup
- [ ] Proxy-derived IP uses a trusted-proxy configuration, not arbitrary `X-Forwarded-For`
- [ ] Every credential check increments the attempt counter, including malformed and batch-carried attempts
- [ ] A successful authentication resets only the intended account/authenticator counters
- [ ] Regression tests cover concurrency, several app instances, Redis failure, and key expiry

## Graduated friction (A06/A07:2025 · ASVS V6 · CWE-645)

- [ ] Response progresses from delay to CAPTCHA to verified recovery step before hard lock
- [ ] Delay has jitter and a maximum; it does not pin server workers or sockets
- [ ] CAPTCHA is server-verified, single-use, short-lived, and risk-triggered
- [ ] CAPTCHA is documented as a cost multiplier, not the only control
- [ ] Legitimate user has a documented path back in that does not expose whether the account exists

## OTP, MFA, and recovery (A07:2025 · ASVS V6 · CWE-307, CWE-799)

- [ ] OTP attempts are capped per challenge/account; cap invalidates the challenge
- [ ] OTP consumption and replay marking are atomic
- [ ] Resend has its own rate and total cap
- [ ] Resend does not reset the failed-attempt counter
- [ ] Issuing a replacement invalidates older out-of-band codes, with race behaviour tested
- [ ] TOTP time step can be accepted only once per account; accepted counter/time-step is persisted
- [ ] Recovery codes are single-use, stored as hashes, and rate limited
- [ ] A correct password followed by failed MFA raises a higher-confidence compromise signal

## Tokens, keys, codes, and IDs (A04/A01/A06:2025 · ASVS V11/V6/V8 · CWE-330, CWE-340, CWE-799)

- [ ] Reset and email verification tokens come from a CSPRNG with enough entropy
- [ ] Tokens are stored hashed where database disclosure would otherwise make them usable
- [ ] Tokens are single-use, expiring, scoped to purpose and account, and atomically consumed
- [ ] API key, invite, coupon, and short-link validation has an attempt budget
- [ ] Secret and HMAC comparison uses a constant-time helper (CWE-208)
- [ ] Sequential IDs are treated as enumerable and every object access still authorizes server-side
- [ ] Switching an ID to UUIDv4 is not reported as an authorization fix

## Batch and alternate paths (API2/API4/API6:2023 · ASVS V4/V6 · CWE-307, CWE-770)

- [ ] GraphQL aliases, arrays, fragments, and batching cannot carry more attempts than counted
- [ ] JSON-RPC/gRPC/batch operations are limited by operation or candidate, not envelope request
- [ ] Gateway body/operation limits backstop application counters
- [ ] Web, mobile, legacy, internal, and partner routes share one limiter policy and store
- [ ] Password reset, registration, token refresh, and support impersonation are reviewed as login-adjacent paths

## Detection and logging (A09:2025 · ASVS V16 · CWE-778)

- [ ] Events include outcome, normalised account hash, source IP/network, device risk, route, limiter action, and timestamp
- [ ] Attempted passwords, OTPs, tokens, API keys, HMACs, and partial values never enter logs
- [ ] Alert sees elevated global failure rate with low failures per account
- [ ] Alert sees many distinct accounts per source/network and many sources per account
- [ ] Alert sees unusual success-after-failure ratio, correct-password/failed-MFA, and limiter-store failure
- [ ] Fixed thresholds are paired with baselines by hour, region, tenant, or channel
- [ ] New-device and impossible-travel signals run after a successful authentication
- [ ] Alert has an owner, runbook, suppression policy, and tested route

## Response (A07/A09:2025 · ASVS V7/V16)

- [ ] Confirmed or likely successful guessing revokes active sessions and refresh-token families
- [ ] Password or affected secret is reset; exposed API keys and recovery codes rotate
- [ ] Review covers email, MFA enrolment, recovery method, API key, forwarding rule, payout, and role changes
- [ ] User notification uses a channel not changed by the attacker where possible
- [ ] Evidence is preserved and `advanced/incident-response` runbook is invoked

## Before Returning

- [ ] Every finding names category, ASVS chapter, CWE, location, precondition, exploitation path, and fix
- [ ] Relevant limiter tests or config validation ran and output is reported honestly
- [ ] Availability tradeoff of failing closed is stated
- [ ] Any gateway, Redis, IdP, or runtime behaviour not inspected is marked unverified
- [ ] No offensive guessing automation, credential list, or candidate-testing tool was produced
