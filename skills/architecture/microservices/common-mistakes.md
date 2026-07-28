# Common Mistakes

| What goes wrong | Why | Fix | Why the fix works |
|---|---|---|---|
| Gateway authorizes once; services trust headers | Any downstream bypass or new route skips policy | Authenticate the workload and re-authorize each action/object at the owner | Policy follows the protected object, not one ingress path |
| “mTLS means internal calls are trusted” | mTLS identifies a peer; it does not grant object access | Use peer identity for endpoint permission, then evaluate subject/action/object policy | Separates transport authentication from authorization |
| One service calls another with its powerful service account for any user request | The callee becomes a confused deputy | Carry bounded user context and enforce current owner-side policy | The callee cannot spend its authority solely because a caller asked |
| Caller sends `tenantId`, `role`, `price`, or `authorized: true` | Payload fields are assertions controlled by the caller | Send identifiers; load authoritative values at the owner | Removes attacker-controlled authority from the contract |
| Services share tables or write credentials | Direct SQL bypasses APIs, policy, auditing, and deployment boundaries | One owner and one write identity per schema; expose an API or minimal event | Makes every mutation pass through the owner boundary |
| A shared “common” model package becomes mandatory everywhere | Services now release in lockstep and accidental fields cross boundaries | Version explicit wire contracts; keep internal models private | Compatibility is negotiated at the contract, not by shared memory shape |
| Discovery accepts a URL or service name from a request | Internal routing becomes an SSRF primitive | Map approved logical names to approved identities; validate scheme, redirect, DNS, and egress | User input cannot choose an arbitrary destination |
| Signed event is treated as authorized | Signature proves producer and integrity, not permission to mutate this object | Consumer validates schema and current object authorization | Prevents a legitimate producer from exercising the consumer's broader privilege |
| Every transient error retries independently | Replicas synchronize into a retry storm | End-to-end deadline, jitter, retry cap, shared budget, bulkhead, idempotency | Bounds amplification and preserves capacity for recovery |
| A request fans out without a concurrency cap | One request consumes every socket and goroutine | Limit parallelism and degrade partial results explicitly | Makes fan-out consume a known budget |
| Pool size is configured per process without replica math | Autoscaling multiplies database connections | Budget `max replicas × dependencies × pool size`, with headroom | Connect capacity remains valid during scale-out |
| Circuit breaker keyed by raw URL, tenant, or object ID | Every new key creates retained state and metrics labels | Key by a finite dependency inventory; cap and evict state | Prevents attacker-controlled cardinality growth |
| Cache key omits tenant or policy version | Cross-tenant data leaks or revoked access persists | Tenant-safe key, bounded entries, short TTL, policy-version invalidation | Isolates data and limits revocation staleness |
| Saga stores the entire request indefinitely | Sensitive context and state accumulate when compensation stalls | Store minimal IDs, encrypt where needed, expire, alert, and assign recovery owner | Bounds retention and makes stuck work visible |
| Queue has no byte/item/age limit | A slow consumer converts traffic into memory or disk exhaustion | Capacity, admission policy, backpressure, DLQ retention, oldest-age alert | Converts hidden growth into controlled rejection or deferral |
| Trace and metric attributes include object IDs or full URLs | Cardinality and exporter queues grow without bound; data leaks into telemetry | Low-cardinality route/dependency labels, attribute length limits, sampling | Bounds telemetry while retaining aggregate diagnosis |
| Health/debug/admin endpoints are absent from the API inventory | “Internal” endpoints become unaudited privileged APIs | Inventory and protect every protocol and management surface | Ownership, auth, and deprecation apply consistently |
| Dual-write is called a migration plan | Partial failure creates two authorities with no stopping point | Single authority, outbox/CDC or bounded compatibility path, reconciliation, cutoff | Failure and rollback have explicit semantics |
| Rollback means only switching traffic back | Writes accepted by the new service may vanish or conflict | Define write disposition, reconciliation, and schema compatibility before rollout | Routing rollback does not discard state |
| A service is extracted because the folder is large | Distribution adds latency and operations without independent ownership | Keep a modular monolith until deploy, scale, compliance, or team boundary earns the split | Avoids paying network costs for a cosmetic seam |

## Wrong fixes

“Put it behind the mesh” does not repair object authorization. “Add retries” can worsen an outage. “Use a shared library” can replace a contract with release coupling. “Cache authorization” can make revocation stale. “Add a circuit breaker” can leak state when keyed by attacker input. Each proposed fix must state the boundary it changes, the resource it retains, and the limit that makes it safe.
