# Standards Mapping for CQRS Failures

Which standard to cite for each failure this skill covers. Versions verified 2026-07-28 against
the source URLs at the bottom.

ASVS is cited at chapter level only. 5.0.0 (released 2025-05-30) renumbered requirements relative
to 4.0.3, so a requirement ID carried over from an older report means something different. Do not
quote one from memory.

## Per failure

| Failure | Top 10 2025 | API Top 10 2023 | ASVS 5.0 | CWE |
|---|---|---|---|---|
| Read model query missing the tenant filter | A01 | API1 | V8 | 1220 |
| Projection omits owner or tenant column | A01, A06 | API1 | V8 | 1220 |
| Denormalised view leaking internal fields | - | API3 | V14 | 213 |
| Command payload accepts arbitrary fields | A01 | API3 | V2 | 915 |
| Authorization decided from a stale projection | A01, A06 | API1 | V8 | 1220 |
| Check-then-act against a projection | A06 | API6 | V2 | 367 |
| Command applied twice on retry | A08 | API6 | V2 | 837 |
| Projector accumulating unbounded state | A06 | API4 | V2 | 401, 770 |
| Unbounded queue between command side and projector | A06 | API4 | V2 | 770 |
| Dual write losing an event | A08 | - | V15 | - |
| Event store holding PII with no erasure path | A04 | - | V11, V14 | 359 |
| Tenant ID taken from the request body | A01 | API1 | V8 | 639 |

Blank cells mean no category in that standard fits well enough to cite. Do not stretch one to fill
the gap - a forced citation is worse than none.

## Why these categories and not others

**A01 Broken Access Control** is the primary category for this skill. The read model is a second
enforcement point for the same data, and a missing tenant or owner filter there is the same failure
class as a missing ownership check on a REST handler. It does not become a different category just
because the code path is a projection.

**A06 Insecure Design** applies when the hole is structural rather than a single missing check. A
projection whose schema has no tenant column is A06: no individual query is wrong, the design makes
correct queries optional. Cite A06 alongside A01 when the fix is a schema change rather than a line
change.

**A08 Software or Data Integrity Failures** covers the dual write and the non-idempotent command.
Both produce state that does not match what happened - a lost event leaves the read model
permanently wrong, and a double-applied command leaves a balance or a count wrong. Neither is an
access control failure.

**A04 Cryptographic Failures** is the category for PII in an event store, because crypto-shredding
makes key management the control. Getting the key hierarchy wrong - one key for all subjects, keys
stored in the event store itself - is what turns the erasure path into a fiction.

**A05 Injection** is not on this list, but it applies the moment a projection query builds SQL from
a sort or filter parameter. Read-model endpoints are usually the ones with flexible filtering, so
check for it. `skills/core/database-security/` covers it.

**A10 Mishandling of Exceptional Conditions** applies if a projector swallows an exception and
advances its position. The event is lost, the projection is wrong, and nothing surfaces.

## CWE notes

Definitions checked at `cwe.mitre.org` on 2026-07-28.

- **CWE-1220 Insufficient Granularity of Access Control** - a policy exists but is too broad, so an
  unauthorized actor reaches a sensitive asset. This is the closest fit for a read model whose
  access control is coarser than the command side's. Base level, mapping allowed.
- **CWE-213 Improper Removal of Sensitive Information Before Storage or Transfer** - data is stored,
  sent, or shared without scrubbing sensitive content first. Fits a projection that copies internal
  columns forward, and the response that then serializes them. (MITRE lists CWE-213 as considered
  for deprecation due to overlap with CWE-359 and CWE-497; if precision matters, use CWE-359 for
  personal data specifically.)
- **CWE-367 Time-of-check Time-of-use** - the resource state changes between the check and the use,
  invalidating the check. Exactly what happens when the check reads a projection and the write
  happens against the authoritative store. Child of CWE-362.
- **CWE-837 Improper Enforcement of a Single, Unique Action** - the product should limit an actor to
  one occurrence of an action but does not. The right CWE for a command applied twice, and better
  than a generic race-condition ID because the harm is business-logic abuse: a double refund, a
  double reservation.
- **CWE-401 Memory Leak** and **CWE-770 Allocation Without Limits or Throttling** - the projector's
  unbounded map and the unbounded queue respectively. `skills/architecture/performance/` owns the
  detail; cite them here and link there.
- **CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes** - mass
  assignment. Applies to a command whose payload is a free-form field map.
- **CWE-639 Authorization Bypass Through User-Controlled Key** - the tenant or owner ID comes from
  the request instead of the session.

## Reporting a CQRS finding

Name the side, because the fix differs by side:

- **Command side** - the rule is missing or reachable around. Fix in the aggregate.
- **Projector** - the projection carries the wrong data, or the projector retains state, or it is
  not idempotent. Fix in the schema or the upsert.
- **Query side** - the query is unscoped, or the shape leaks fields. Fix in the repository
  signature, the projection key, and row-level security together.

Then state whether the fix removes the option or relies on discipline. "Add a tenant filter to this
query" relies on discipline. "Tenant is a required parameter, part of the primary key, and enforced
by row-level security" removes the option. Prefer the second, and say which one you delivered.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- CWE-213 - <https://cwe.mitre.org/data/definitions/213.html>
- CWE-367 - <https://cwe.mitre.org/data/definitions/367.html>
- CWE-837 - <https://cwe.mitre.org/data/definitions/837.html>
- CWE-1220 - <https://cwe.mitre.org/data/definitions/1220.html>
