# CWE entries for guessing attacks

The weaknesses this skill maps findings to. Use the CWE for precision, the Top 10 category for
reporting. Names below are the MITRE entry titles.

Source: <https://cwe.mitre.org/data/index.html> · individual entries at
`https://cwe.mitre.org/data/definitions/<id>.html`
Verified: 2026-07-28

| CWE | Title | Use it when |
|---|---|---|
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | The primary entry. No limit, or a limit that does not bind, on an authentication attempt counter |
| CWE-799 | Improper Control of Interaction Frequency | Non-authentication flows with no attempt cap: OTP verification, coupon redemption, API key probing, search |
| CWE-645 | Overly Restrictive Account Lockout Mechanism | Lockout that an unauthenticated attacker can trigger against a named victim |
| CWE-204 | Observable Response Discrepancy | Different message, status code, or response body for "no such user" versus "wrong password" |
| CWE-208 | Observable Timing Discrepancy | Early return on a missing account, or `==` on a secret comparison |
| CWE-180 | Incorrect Behavior Order: Validate Before Canonicalize | The limiter keys raw input while account lookup later normalises it |
| CWE-294 | Authentication Bypass by Capture-replay | A valid TOTP is accepted more than once during the same time step |
| CWE-330 | Use of Insufficiently Random Values | Tokens, codes, or identifiers from a non-CSPRNG source |
| CWE-340 | Generation of Predictable Numbers or Identifiers | Sequential IDs, timestamp-seeded tokens, counter-derived invite codes |
| CWE-521 | Weak Password Requirements | No length floor, no breached-password check - the guess space is small enough to matter |
| CWE-532 | Insertion of Sensitive Information into Log File | Attempted passwords, OTPs, keys, tokens, or partial values enter logs |
| CWE-770 | Allocation of Resources Without Limits or Throttling | One request carrying many attempts: GraphQL batches, JSON-RPC arrays, unbounded array parameters |
| CWE-778 | Insufficient Logging | Guessing events are not recorded well enough to detect or investigate |
| CWE-862 | Missing Authorization | A guessed or leaked object ID grants access because ownership is never checked |

## Picking between the close ones

CWE-307 and CWE-799 overlap. 307 is specific to authentication attempts; 799 covers any
interaction frequency. An unlimited login is 307. An unlimited coupon-code check is 799.

CWE-330 and CWE-340 also overlap. 330 is about the source of randomness (`Math.random()`,
`rand()`, `random`). 340 is about the resulting value being predictable, including cases where no
randomness was intended at all (`id + 1`). A UUIDv1 built from a MAC address and a timestamp is
340, not 330.

CWE-204 and CWE-208 are the same finding through two channels. If the code returns early when
the account does not exist, cite both: the response differs and so does the timing.

## Mapping to the Top 10 2025

| CWE | Top 10 2025 |
|---|---|
| CWE-307, CWE-521, CWE-204, CWE-208 | A07 Authentication Failures |
| CWE-799, CWE-770, CWE-645 | A06 Insecure Design, or A07 when the flow is authentication |
| CWE-330, CWE-340 | A04 Cryptographic Failures when the value is a secret; A01 when it is an authorization-relevant identifier |

An absent limit is a design finding as much as an implementation one. If the design document
never named an attempt budget, A06 is the honest category and the missing counter is a symptom.

## What CWE does not give you

A CWE ID is a classification, not an exploitability argument. "CWE-307" on an endpoint that sits
behind a gateway already enforcing five attempts per minute is not a finding. Check whether the
limit exists somewhere in the path before citing the weakness.
