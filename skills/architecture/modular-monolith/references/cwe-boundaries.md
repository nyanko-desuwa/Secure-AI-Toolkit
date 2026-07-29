# CWE Boundary and Resource Mappings

Verified 2026-07-28 against the linked MITRE CWE entries. Use these only where the mechanism matches.

| CWE | Verified name | Use here |
|---|---|---|
| CWE-602 | Client-Side Enforcement of Server-Side Security | A controller/client/caller is trusted to enforce a rule the owning module does not repeat |
| CWE-653 | Improper Isolation or Compartmentalization | Modules share private tables, repositories, roles, or mutable implementation state |
| CWE-770 | Allocation of Resources Without Limits or Throttling | In-process queue, cache, listener registrations, batches, or fan-out have no bound |
| CWE-772 | Missing Release of Resource after Effective Lifetime | Transactions, connections, cursors, streams, listeners, locks, timers, or tasks outlive their owner |
| CWE-1220 | Insufficient Granularity of Access Control | A broad generic repository/API exposes more records, fields, or operations than the caller needs |

## Selection Notes

Use CWE-602 when enforcement exists only outside the authoritative module. It is not a claim that
all controllers are clients; the relevant fact is that an upstream caller supplies the only check.

Use CWE-653 for a missing compartment: shared write access, cross-module persistence imports, or a
database role that can bypass ownership. Use CWE-1220 when the access surface is too broad, such as a
generic query API or contract that exposes private fields. A finding can involve both, but cite only
the mechanisms actually evidenced.

Use CWE-770 for no maximum or throttling. Use CWE-772 for no release after effective lifetime. A
listener list may involve both when registrations are unlimited and disposers are absent. State what
grows and which object/handle remains held.

## Sources

- CWE-602 - <https://cwe.mitre.org/data/definitions/602.html>
- CWE-653 - <https://cwe.mitre.org/data/definitions/653.html>
- CWE-770 - <https://cwe.mitre.org/data/definitions/770.html>
- CWE-772 - <https://cwe.mitre.org/data/definitions/772.html>
- CWE-1220 - <https://cwe.mitre.org/data/definitions/1220.html>
