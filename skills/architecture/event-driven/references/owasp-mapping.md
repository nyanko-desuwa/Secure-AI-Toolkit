# Standards Mapping for Event-Driven Failures

Which OWASP category and ASVS chapter to cite for each hazard in this skill. Categories and
chapter lists verified 2026-07-28 against the sources at the bottom.

OWASP Top 10 2025 is not a renumbering of 2021. A03 Software Supply Chain Failures and A10
Mishandling of Exceptional Conditions are new, and Injection moved from A03 to A05. A report
that says "A03 Injection" is citing the 2021 list, which makes the rest of the report suspect.

ASVS 5.0.0 (released 2025-05-30) renumbered requirements relative to 4.0.3. Cite chapters only.
A requirement ID carried across from an older document points somewhere else now, and an invented
one is worse than no citation at all.

## Per hazard

| Hazard | Top 10 2025 | ASVS 5.0 chapter | CWE |
|---|---|---|---|
| E1 Consumer trusts identity in the payload | A01 | V8 Authorization | 602, 863, 1220 |
| E1 Producer decided authorization, consumer never re-checked | A01, A06 | V8 | 602 |
| E1 Unauthenticated publisher can impersonate a producer | A07, A08 | V6, V15 | 290 |
| E2 Fat event carrying data a subscriber may not see | A01 | V8, V14 Data Protection | 359, 1220 |
| E2 PII retained on the topic longer than the request | A04 | V14 | 359 |
| E2 Replay re-emitting personal data to new consumers | A04, A06 | V14 | 359 |
| E3 Polymorphic or type-embedded deserialization | A08 | V15 Secure Coding and Architecture | 502 |
| E4 Non-idempotent handler, duplicate side effect | A06, A08 | V2 Validation and Business Logic | 799 |
| E4 Dedupe key store with no TTL, key user-controlled | A06 | V2 | 770, 400 |
| E5 Ordering assumed, state overwritten by a stale event | A06 | V2 | 841 |
| E6 Poison message with no DLQ, partition stalls | A10 | V16 Logging and Error Handling | 400 |
| E6 DLQ nobody drains or alerts on | A09, A10 | V16 | 772 |
| E6 Poison handler logging the whole payload | A09 | V16, V14 | 532 |
| E7 Producer adds a required field, consumers crash | A08, A10 | V15 | - |
| E8 One shared broker credential across services | A02, A07 | V13 Configuration | 522 |
| E8 No topic-level authorization | A01, A02 | V8, V13 | 1220 |
| E8 Plaintext transport to the broker | A04 | V12 Secure Communication | - |
| E9 Handler subscribed and never removed | A06 | V15 | 401 |
| E9 In-memory bus with no backpressure | A06 | V15 | 770, 400 |
| E9 Uncapped retry against a failing dependency | A10 | V15 | 400, 799 |
| E9 Saga context held until a timeout that never fires | A06 | V15 | 772 |
| E9 Connection or transaction held across an await | A06 | V15 | 772 |

Blank means no category in that standard fits closely enough. Do not stretch one to fill the gap.

## Why these categories

A01 Broken Access Control is the primary category for this skill. A consumer that acts on
`event.role` has an access control failure, not a messaging bug. The decision was made once on
the request path and then re-made from data an attacker can write. It does not become a different
category because the code path is a message handler.

A06 Insecure Design applies when the hole is structural rather than a single missing check. An
event contract that carries `tenantId` at all invites E1: no individual handler is wrong, the
design makes trusting the payload the natural thing to do. Cite A06 alongside A01 when the fix is
a contract change rather than a line change.

A08 Software or Data Integrity Failures covers deserialization (E3), unsigned events on a shared
broker, and schema breaks that corrupt state. The common thread is data that is accepted as
trustworthy without verification.

A09 Security Logging and Alerting Failures covers both directions of the logging problem: a DLQ
with no alert is missing telemetry, and a handler that logs the full payload is telemetry that
leaks. Both live in the same handler, usually three lines apart.

A10 Mishandling of Exceptional Conditions is new in 2025 and it is the natural home for the
failure path. A handler that catches everything and acks, a retry with no ceiling, a poison
message that stalls a partition - all are exceptional conditions handled by pretending they did
not happen.

A02 Security Misconfiguration and A07 Authentication Failures cover E8. A shared broker username
in every service's config is misconfiguration; the fact that the broker cannot then distinguish
producers is an authentication failure.

A05 Injection is not in the table, but it applies the moment a field from an event body reaches a
query, a shell, or a template. Consumers are commonly written as if the payload were already
validated. `skills/core/database-security/` covers the query side.

A03 Software Supply Chain Failures applies to the broker client library and the serialization
library, which is where most historical deserialization gadget chains actually lived. Out of
scope here, named so it is not assumed forgotten.

## ASVS chapters used here

- V2 Validation and Business Logic - schema validation of the payload, idempotency and
  duplicate-submission control, business-logic limits.
- V8 Authorization - the consumer-side decision, and the topic-level decision.
- V11 Cryptography - signing an event or encrypting a field within it.
- V12 Secure Communication - TLS to the broker, certificate verification.
- V13 Configuration - per-service credentials, secret handling, broker settings.
- V14 Data Protection - payload minimisation, retention, personal data in a replayable log.
- V15 Secure Coding and Architecture - deserialization, resource lifecycle, integrity of
  inter-service messages.
- V16 Security Logging and Error Handling - what the poison-message path records and what it
  must not.

## Reporting a finding

Name the side, because the fix differs by side:

- Producer - the event carries too much, or claims authority it cannot prove. Fix the contract.
- Broker - no topic authorization, one shared credential, no TLS, no retention policy. Fix the
  configuration, and say plainly that you could not verify the live setting from source.
- Consumer - trusts the payload, is not idempotent, has no failure path, leaks resources. Fix the
  handler.

Then state whether the fix removes the option or relies on discipline. "Do not read `role` from
the event" relies on discipline. "The event type has no `role` field, so reading one does not
compile" removes it. Prefer the second and say which one you delivered.

One CWE plus one OWASP category is enough per finding. Five identifiers on one line reads as
generated rather than investigated.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/> (categories pinned by the repository brief,
  verified 2026-07-28)
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
  (5.0.0, released 2025-05-30; chapter list pinned by the repository brief, verified 2026-07-28)
- CWE - <https://cwe.mitre.org/> (individual entries and verification dates in
  [cwe-event-driven.md](cwe-event-driven.md))
