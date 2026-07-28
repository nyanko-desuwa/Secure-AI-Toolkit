# Prompt Examples

Prompts that produce defensive findings. Each states the surface, attack shape, and answer format.
Nothing here asks the assistant to try credentials or generate attack tooling.

## Inventory every guessing surface

```text
Read the authentication and account-recovery routes in this repository. Inventory every value an
unauthenticated caller can guess: password, OTP, reset/verification token, recovery code, API key,
invite/coupon code, short URL, and customer identifier. For each, report candidate-space size,
lifetime, attempts allowed, limiter dimensions, Top 10 2025 category, ASVS 5.0 chapter, and CWE.
Do not test real credentials.
```

Why it works: login does not consume the whole review. Candidate space and allowed attempts turn a
vague "weak token" comment into an exploitation path.

## Review a distributed limiter

```text
Review src/security/rateLimiter.ts and every call site. Check account normalisation, account/IP/
subnet/device/global dimensions, atomicity, expiry, cross-pod storage, fail-closed behavior, trusted
proxy handling, and resets after success. Show vulnerable and fixed code. Include regression tests
for 50 concurrent requests, two service instances, and Redis failure.
```

## Separate brute force from spraying

```text
Classify the login alerts and controls as brute force, credential stuffing, password spraying, or
reverse brute force. Prove whether three failures per account across 10,000 accounts would trigger
anything. Propose defensive aggregate alert queries and limiter changes. Do not create candidate
lists or login automation.
```

The proof target forces examination of global/account-breadth signals instead of treating a
per-account lockout as complete.

## Review OTP and resend

```text
Review the OTP verification and resend flow. Assume the attacker knows the account identifier and
can rotate source addresses. Check atomic attempt caps per account/challenge, invalidation on cap,
single use, expiry, resend budget, whether resend resets failures, replacement-code behavior, and
TOTP replay within one time step. Map findings to A07:2025, ASVS V6, CWE-307/CWE-799.
```

## Find one-request-many-attempt bypasses

```text
Review GraphQL, JSON-RPC, gRPC, and batch endpoints for operations that compare a credential,
token, code, or key. Prove whether one transport request with 100 operations consumes one attempt
or 100. Add an operation/body backstop and consume the limiter inside each verifier. Give only
defensive tests with invalid synthetic values.
```

## Audit alternate login paths

```text
Trace every path that establishes the same user authority: browser login, mobile API, legacy
endpoint, basic auth, SSO callback, device flow, password grant, support tool, and internal route.
For each path, state the shared limiter service/store and policy. Report any path that bypasses it
with file:line, exploit precondition, A07:2025, ASVS V6, and CWE-307.
```

## Design detection and alerting

```text
Using our authentication event schema, design alerts for password spraying and successful
guessing. Cover elevated global failures with low per-account counts, distinct accounts per
source/network, sources per account, success-after-failure, correct-password/failed-MFA, new
device, and impossible travel. Pair every fixed threshold with a baseline. List fields that must
never be logged. Map to A09:2025 and ASVS V16.
```

## Review token and identifier generation

```text
Review all reset tokens, verification tokens, invite/coupon codes, short links, API keys, and
customer-facing IDs. Identify non-CSPRNG, timestamp/counter/sequential inputs, missing purpose or
expiry, non-atomic consumption, timing-unsafe comparison, and missing attempt budgets. Explain why
UUIDv4 raises enumeration cost but is not authorization. Map CWE-330, CWE-340, CWE-208, CWE-799,
and A01 where object access is unscoped.
```

## Exercise fail-closed behaviour safely

```text
Add a defensive test that replaces the limiter client with an unavailable stub. Assert login does
not call password verification and returns the documented temporary failure. Assert an alert event
contains route/correlation metadata but no password, account plaintext, or token. State the
availability tradeoff; do not change production infrastructure.
```

## Plan response to a likely successful guess

```text
Given a high-confidence success-after-spray alert, produce the containment checklist. Include
session and refresh-token revocation, forced reset, API/recovery-key rotation, review of email/MFA/
recovery/forwarding/payout/role changes, evidence preservation, and notification through an
unchanged channel. Cross-link advanced/incident-response. Do not attempt to validate the guessed
credential.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Brute-force this login to check it" | Requests offensive automation and risks real account access. Review configuration and write a limiter-engagement test instead |
| "Try common passwords against staging" | Still credential spraying. Synthetic test accounts and an invalid fixed candidate prove the counter without finding valid credentials |
| "Make a credential-stuffing script for defence" | Combo-list handling is attack tooling. Build alert queries, fixtures, and policy tests |
| "Add rate limiting" | No attack shape, dimension, window, failure behavior, or alternate-path scope |
| "Lock the account after five failures" | Gives any unauthenticated caller a DoS switch (CWE-645) |
| "Put CAPTCHA on login" | CAPTCHA is a bypassable cost multiplier, not a limiter |
| "Switch IDs to UUIDs" | Raises enumeration cost but leaves A01 broken if object access is unscoped |
| "Alert at 100 failures" | Fixed threshold without time window, baseline, cardinality, route, or owner is noise |
| "Log the attempted token prefix for debugging" | Every logged bit reduces the remaining search space and leaks into the log pipeline |
| "Use an in-memory counter; we can add Redis later" | Horizontal scaling and restart bypass it immediately |
