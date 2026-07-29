# OWASP Top 10 2025 Mapping

Verified 2026-07-28 against <https://owasp.org/Top10/2025/>.

The 2025 edition is not a renumbering of 2021. This skill uses only the categories below.

| Category | Modular-monolith use |
|---|---|
| A01 Broken Access Control | Missing actor, caller-only authorization, cross-module table access, tenant-less queries/cache keys, excessive contract fields |
| A05 Injection | Generic query/criteria contracts, unvalidated command fields, unsafe dynamic SQL inside adapters |
| A06 Insecure Design | Boundaries without enforcement, no queue/cache/retry bounds, event treated as capability, no failure/consistency design |
| A08 Software or Data Integrity Failures | Event/state ordering or untrusted event processing where integrity is affected |
| A10 Mishandling of Exceptional Conditions | Transactions, cursors, listeners, or handles not cleaned up on rollback, timeout, cancellation, or shutdown |

A01 is the primary category when retained actor state or a missing tenant predicate exposes another
principal's data. A06 is primary when the design omitted ownership, bounds, or an intermediate-state
policy. A10 applies to exceptional-path cleanup and rollback handling.

Do not infer severity from category. Report the bypass path, actor precondition, data/resource at
risk, and whether a database/compiler/runtime control blocks it.

## Source

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
