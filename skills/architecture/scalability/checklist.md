# Scalability Checklist

Mark each applicable item pass, fail, or not applicable with a reason. A diagram, default, or config
file is not proof of runtime behavior.

## Baseline and Boundaries

- [ ] Public, service, tenant, cache, queue, pool, and dependency boundaries are drawn
- [ ] Every route to the service is known, including internal and legacy routes that bypass gateways
- [ ] The maximum current and configured replica counts are recorded
- [ ] Per-request queries, downstream calls, bytes, CPU, and connection hold time are measured
- [ ] Measurements include p50 and p99 input shapes and name workload duration and offered rate
- [ ] Every stated limit has a unit, owner, source, alert, and saturation behavior

## S1 — Concurrency

- [ ] Every fan-out loop has a semaphore, worker count, or equivalent hard ceiling
- [ ] Concurrency is bounded before tasks or promises are created, not after
- [ ] Queue wait and execution share a total deadline; canceled callers cancel downstream work
- [ ] Per-dependency concurrency is separate, so one slow dependency cannot consume all workers
- [ ] The bound is derived from downstream capacity and maximum replicas, not CPU count alone
- [ ] In-flight count, wait duration, rejection, and timeout are metrics

## S2 — Backpressure and Load Shedding

- [ ] Every queue, channel, stream buffer, and batch has a maximum depth or bytes
- [ ] Full behavior is explicit: block briefly, reject, degrade, or drop disposable work
- [ ] Public saturation returns `503` with a bounded `Retry-After`; quota returns `429`
- [ ] Streaming code propagates backpressure and closes producers when clients disconnect
- [ ] Admission happens before expensive parsing, allocation, database work, or downstream calls
- [ ] Load tests show queue and memory stabilize above sustainable throughput

## S3/S4 — Shared Cache Integrity and Tenant Isolation

- [ ] Cache keys include tenant or authorization scope for every private representation
- [ ] Keys include representation version and every response-varying input
- [ ] Raw user input cannot choose an internal cache namespace without canonicalization and bounds
- [ ] Only authorized, validated origin responses populate shared entries
- [ ] Errors, redirects, and responses containing per-user data are not shared by default
- [ ] Entry count or bytes, item size, TTL, negative TTL, and stampede lock are bounded
- [ ] Authorization revocation behavior is stated; TTL is treated as a staleness window
- [ ] Two-tenant tests prove identical resource IDs never share values
- [ ] Hit rate, evictions, fill errors, entry bytes, and rejected oversized entries are metrics

## S5 — Rate Limits Across Replicas

- [ ] Authenticated limits key on verified actor/client identity, not a caller-supplied header
- [ ] Pre-auth IP comes only from a trusted proxy chain that strips client copies
- [ ] Counters use an atomic shared store or a single enforced edge all traffic traverses
- [ ] A test distributes requests over all replicas and observes one aggregate allowance
- [ ] Limits exist per costly operation, not only globally
- [ ] Local emergency shedding exists if the shared limiter is slow or unavailable
- [ ] Limiter failure behavior is explicit and differs for critical and low-risk operations
- [ ] Decision count, store latency, 429 count, bypass/fallback count, and key cardinality are metrics

## S6 — Database Query and Pool Budget

- [ ] List endpoints assert a maximum query count independent of returned row count
- [ ] Relationships are joined, eager-loaded, or batch-loaded; no query inside an unbounded row loop
- [ ] Page size is server-capped and deep pages use keyset pagination
- [ ] Pool size per replica times maximum replicas fits the database limit with headroom
- [ ] Pool acquisition has a short timeout and transaction scope excludes network calls
- [ ] Cursors, rows, transactions, and connections release on every error and cancellation path
- [ ] Statement timeout and maximum result rows/bytes are set where supported
- [ ] Queries/request, pool wait, active/idle connections, timeouts, and transaction age are metrics

## S7 — Autoscaling Safety

- [ ] Maximum replicas are limited by the tightest downstream connection or request quota
- [ ] Scaling metrics represent useful throughput, queue age, or saturation, not CPU alone
- [ ] A dependency outage cannot trigger unlimited scale-out or unlimited worker concurrency
- [ ] Scale-up stabilization/cooldown prevents rapid oscillation and cache cold-start storms
- [ ] Readiness does not pass until required pools and caches can safely serve work
- [ ] Scale-down drains requests, queues, leases, and subscriptions before termination
- [ ] A slow-dependency test proves replicas, connection totals, and downstream QPS stay bounded

## S8 — Retry and Stampede Protection

- [ ] Retries have capped attempts, exponential backoff, jitter, and a total deadline
- [ ] Retries occur only for classified transient failures and safe/idempotent operations
- [ ] Retry budget is shared across layers; one request cannot retry at gateway, service, and client
- [ ] Expensive cache fills use single-flight or a bounded lock with expiry
- [ ] Stale-if-error or degradation is limited to data safe to serve stale
- [ ] Retry amplification, circuit state, cache fill concurrency, and stale responses are metrics

## Resource Lifetime

- [ ] Caches, limiter keys, dedupe records, queues, and correlation maps have hard bounds and expiry
- [ ] Pools and clients are process-owned, created once, and closed on shutdown
- [ ] Timers, listeners, tasks, and subscriptions have owners and teardown paths
- [ ] Input-derived allocations have byte/count caps (`CWE-789` where one allocation is excessive)
- [ ] Heap or RSS growth at steady accepted throughput has been checked with the `performance` skill

## Standards and Reporting

- [ ] Cross-tenant cache exposure is reported as `A01:2025` / ASVS V8, not merely performance
- [ ] Unset platform limits are mapped to `A02:2025` / ASVS V13
- [ ] Missing design bounds map to `A06:2025` / `API4:2023` / ASVS V4 or V15
- [ ] Missing saturation telemetry maps to `A09:2025` / ASVS V16 where consequential
- [ ] Failure amplification and skipped cleanup map to `A10:2025` / ASVS V16 where applicable
- [ ] Only verified `CWE-400/401/770/772/789` identifiers are used
- [ ] Every recommendation states security boundary, runtime cost, and when it should not be used

## Before Returning

- [ ] Runnable examples compile or execute with documented commands
- [ ] Tests include saturation, two tenants, multiple replicas, N+1 count, and slow dependency as applicable
- [ ] Observed values are separated from illustrative starting values
- [ ] Anything requiring deployed configuration or runtime evidence is labelled unverified
- [ ] No load test targets an unapproved system and no sensitive metric payload is retained
