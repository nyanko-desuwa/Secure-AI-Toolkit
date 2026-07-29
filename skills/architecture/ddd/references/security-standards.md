# Security Standards for DDD Boundaries

Verified 2026-07-28. Citations are deliberately narrow: a structural pattern is mapped to a
standard only where there is an actual authorization, trust, integrity, or resource failure.
DDD terminology by itself is not a vulnerability class.

## OWASP Top 10 2025

Source: <https://owasp.org/Top10/2025/>

| Category | Use it here when | Do not use it for |
|---|---|---|
| A01 Broken Access Control | Contexts share tenant data; a write path bypasses aggregate authorization; event consumer acts without re-authorizing | Aggregate too large with no access consequence |
| A02 Security Misconfiguration | DB role exists but has broad grants; queue/handler limit exists but is left unset | A boundary that was never designed - that is A06 |
| A06 Insecure Design | Design has no isolation, no resource bound, or no consistent place to enforce a business control | Any incorrect line merely because it is "architecture" |
| A08 Software or Data Integrity Failures | Event is published before commit and consumers act on rolled-back state | Every eventual-consistency window |
| A09 Security Logging and Alerting Failures | Full-entity event or logger leaks sensitive fields; consequential transition leaves no audit event | Naming disagreement |
| A10 Mishandling of Exceptional Conditions | Authorization or invariant check fails open; compensation/retry failure leaves an unsafe state | Ordinary domain validation rejection |

The 2025 categories are not a renumbering of 2021. Injection is A05 in 2025; A03 is Software
Supply Chain Failures; A10 is Mishandling of Exceptional Conditions.

## OWASP ASVS 5.0.0

Released 30 May 2025. Source:
<https://owasp.org/www-project-application-security-verification-standard/>

Cite chapters only in this skill. Do not invent requirement IDs.

| Chapter | DDD use |
|---|---|
| V2 Validation and Business Logic | Value-object construction, aggregate invariants, transition rules, cross-aggregate race design |
| V4 API and Web Service | Published cross-context API contracts and event inputs |
| V8 Authorization | Tenant-scoped repositories, aggregate write paths, consumer re-authorization |
| V14 Data Protection | Minimal event payloads and preventing internal fields from leaving a context |
| V15 Secure Coding and Architecture | Context isolation, ACL integration seam, enforceable structural boundary |
| V16 Security Logging and Error Handling | Audit events, fail-closed consumers, compensation failures |

Do not claim an ASVS level from this skill. "Mapped to ASVS V8" means the authorization
chapter is relevant, not that a formal Level 1/2/3 assessment was completed.

## CWE Mapping

CWE pages: <https://cwe.mitre.org/>

### CWE-653 - Improper Isolation or Compartmentalization

Use when two bounded contexts have different trust or ownership but share writable storage,
credentials, or unrestricted internal interfaces. This is the direct mapping for a context
boundary that exists on a diagram but not in grants.

Source: <https://cwe.mitre.org/data/definitions/653.html>

### CWE-1220 - Insufficient Granularity of Access Control

Use when the policy is too coarse: one shared table/role controls data for two contexts, or
primitive ID types allow a tenant scope to be substituted by another identifier with the
same representation.

Source: <https://cwe.mitre.org/data/definitions/1220.html>

### CWE-284 - Improper Access Control

Use for the general case where a second write path mutates aggregate state without the
required authorization or ownership control. Prefer a more specific child weakness when one
fits the actual path.

Source: <https://cwe.mitre.org/data/definitions/284.html>

### CWE-863 - Incorrect Authorization

Use when an event consumer trusts `approvedBy`, `role`, or another claim in the message and
performs a consequential action without checking its own authoritative state. The event is a
message, not a capability.

Source: <https://cwe.mitre.org/data/definitions/863.html>

### CWE-501 - Trust Boundary Violation

Use when a vendor/legacy DTO is passed directly into domain state, mixing trusted and
untrusted fields in the same object or message. The anti-corruption layer is the translation
and validation point.

Source: <https://cwe.mitre.org/data/definitions/501.html>

### CWE-362 - Concurrent Execution using Shared Resource with Improper Synchronization

Use when a cross-aggregate invariant is checked from two in-memory snapshots and concurrent
transactions can both pass. The fix must serialize through one version/lock/constraint, or
accept eventual consistency with compensation.

Source: <https://cwe.mitre.org/data/definitions/362.html>

### CWE-401 - Missing Release of Memory after Effective Lifetime

Use when a handler is subscribed and never removed, and the bus retains the handler and its
captured graph after the intended scope ends. Runtime proof requires a heap/retainer check;
source can establish that the release point is absent.

Source: <https://cwe.mitre.org/data/definitions/401.html>

### CWE-662 - Improper Synchronization

Use where publish/commit ordering lets a consumer act on state before its transaction
commits, or where concurrent workflow state is advanced without the necessary ordering.
CWE-362 may be more specific when the demonstrated failure is a concrete race.

Source: <https://cwe.mitre.org/data/definitions/662.html>

### CWE-770 - Allocation of Resources Without Limits or Throttling

Use for unbounded event queues, repository list methods with no maximum, or in-memory read
models that grow once per domain object with no eviction.

Source: <https://cwe.mitre.org/data/definitions/770.html>

## Mapping Table

| Finding | Top 10 | ASVS | CWE |
|---|---|---|---|
| Two contexts share a tenant-filtered table | A01, A06 | V8, V15 | 653, 1220 |
| Second writer bypasses aggregate authorization | A01 | V8 | 284 |
| Primitive tenant/user IDs swapped | A01 | V2, V8 | 1220 |
| Full entity in event payload | A01, A09 | V14, V16 | 200 where sensitive data is exposed |
| Consumer trusts event's authority claim | A01 | V8 | 863 |
| External DTO enters domain unchanged | A06 | V2, V15 | 501 |
| Cross-aggregate in-memory race | A06 | V2 | 362 |
| Handler never unsubscribed | A06 | V15 | 401 |
| Event published before commit | A08 | V2 | 662 |
| Repository returns lazy query, caller omits scope | A01 | V8 | 284 |
| Unbounded dispatcher/read model/list method | A06 | V15 | 770 |

## No-CWE Cases

Say "no CWE, this is a correctness defect" when that is true. Examples:

- Ubiquitous language does not match the domain expert, with no wrong authorization or data
  consequence shown
- Aggregate is somewhat larger than necessary, but no resource exhaustion or race is shown
- Eventual consistency is visible to a reader but the product explicitly permits it
- A repository abstraction is awkward but no boundary, integrity, or resource failure exists

A pattern smell is not automatically a vulnerability. Report the exploitation or failure
path; otherwise call it maintainability or correctness.
