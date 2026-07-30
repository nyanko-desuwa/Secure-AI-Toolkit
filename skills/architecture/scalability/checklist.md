# Scalability Checklist

Mark each applicable item pass, fail, or not applicable with a reason. A diagram, default, or config
file is not proof of runtime behavior.

## Baseline and Boundaries

- [ ] [recommended] Public, service, tenant, cache, queue, pool, and dependency boundaries are drawn
- [ ] [recommended] Every route to the service is known, including internal and legacy routes that bypass gateways
- [ ] [recommended] The maximum current and configured replica counts are recorded
- [ ] [recommended] Per-request queries, downstream calls, bytes, CPU, and connection hold time are measured
- [ ] [recommended] Measurements include p50 and p99 input shapes and name workload duration and offered rate
- [ ] [recommended] Every stated limit has a unit, owner, source, alert, and saturation behavior

## S1 - Concurrency

- [ ] [critical] Every fan-out loop has a semaphore, worker count, or equivalent hard ceiling
- [ ] [recommended] Concurrency is bounded before tasks or promises are created, not after
- [ ] [recommended] Queue wait and execution share a total deadline; canceled callers cancel downstream work
- [ ] [recommended] Per-dependency concurrency is separate, so one slow dependency cannot consume all workers
- [ ] [recommended] The bound is derived from downstream capacity and maximum replicas, not CPU count alone
- [ ] [recommended] In-flight count, wait duration, rejection, and timeout are metrics

## S2 - Backpressure and Load Shedding

- [ ] [critical] Every queue, channel, stream buffer, and batch has a maximum depth or bytes
- [ ] [recommended] Full behavior is explicit: block briefly, reject, degrade, or drop disposable work
- [ ] [recommended] Public saturation returns `503` with a bounded `Retry-After`; quota returns `429`
- [ ] [recommended] Streaming code propagates backpressure and closes producers when clients disconnect
- [ ] [recommended] Admission happens before expensive parsing, allocation, database work, or downstream calls
- [ ] [recommended] Load tests show queue and memory stabilize above sustainable throughput

## S3/S4 - Shared Cache Integrity and Tenant Isolation

- [ ] [critical] Cache keys include tenant or authorization scope for every private representation
- [ ] [critical] Keys include representation version and every response-varying input
- [ ] [critical] Raw user input cannot choose an internal cache namespace without canonicalization and bounds
- [ ] [critical] Only authorized, validated origin responses populate shared entries
- [ ] [critical] Errors, redirects, and responses containing per-user data are not shared by default
- [ ] [recommended] Entry count or bytes, item size, TTL, negative TTL, and stampede lock are bounded
- [ ] [recommended] Authorization revocation behavior is stated; TTL is treated as a staleness window
- [ ] [critical] Two-tenant tests prove identical resource IDs never share values
- [ ] [recommended] Hit rate, evictions, fill errors, entry bytes, and rejected oversized entries are metrics

## S5 - Rate Limits Across Replicas

- [ ] [critical] Authenticated limits key on verified actor/client identity, not a caller-supplied header
- [ ] [critical] Pre-auth IP comes only from a trusted proxy chain that strips client copies
- [ ] [critical] Counters use an atomic shared store or a single enforced edge all traffic traverses
- [ ] [recommended] A test distributes requests over all replicas and observes one aggregate allowance
- [ ] [recommended] Limits exist per costly operation, not only globally
- [ ] [recommended] Local emergency shedding exists if the shared limiter is slow or unavailable
- [ ] [recommended] Limiter failure behavior is explicit and differs for critical and low-risk operations
- [ ] [recommended] Decision count, store latency, 429 count, bypass/fallback count, and key cardinality are metrics

## S6 - Database Query and Pool Budget

- [ ] [recommended] List endpoints assert a maximum query count independent of returned row count
- [ ] [recommended] Relationships are joined, eager-loaded, or batch-loaded; no query inside an unbounded row loop
- [ ] [recommended] Page size is server-capped and deep pages use keyset pagination
- [ ] [critical] Pool size per replica times maximum replicas fits the database limit with headroom
- [ ] [recommended] Pool acquisition has a short timeout and transaction scope excludes network calls
- [ ] [critical] Cursors, rows, transactions, and connections release on every error and cancellation path
- [ ] [recommended] Statement timeout and maximum result rows/bytes are set where supported
- [ ] [recommended] Queries/request, pool wait, active/idle connections, timeouts, and transaction age are metrics

## S7 - Autoscaling Safety

- [ ] [critical] Maximum replicas are limited by the tightest downstream connection or request quota
- [ ] [recommended] Scaling metrics represent useful throughput, queue age, or saturation, not CPU alone
- [ ] [critical] A dependency outage cannot trigger unlimited scale-out or unlimited worker concurrency
- [ ] [recommended] Scale-up stabilization/cooldown prevents rapid oscillation and cache cold-start storms
- [ ] [recommended] Readiness does not pass until required pools and caches can safely serve work
- [ ] [recommended] Scale-down drains requests, queues, leases, and subscriptions before termination
- [ ] [recommended] A slow-dependency test proves replicas, connection totals, and downstream QPS stay bounded

## S8 - Retry and Stampede Protection

- [ ] [critical] Retries have capped attempts, exponential backoff, jitter, and a total deadline
- [ ] [critical] Retries occur only for classified transient failures and safe/idempotent operations
- [ ] [recommended] Retry budget is shared across layers; one request cannot retry at gateway, service, and client
- [ ] [recommended] Expensive cache fills use single-flight or a bounded lock with expiry
- [ ] [recommended] Stale-if-error or degradation is limited to data safe to serve stale
- [ ] [recommended] Retry amplification, circuit state, cache fill concurrency, and stale responses are metrics

## Resource Lifetime

- [ ] [critical] Caches, limiter keys, dedupe records, queues, and correlation maps have hard bounds and expiry
- [ ] [recommended] Pools and clients are process-owned, created once, and closed on shutdown
- [ ] [recommended] Timers, listeners, tasks, and subscriptions have owners and teardown paths
- [ ] [recommended] Input-derived allocations have byte/count caps (`CWE-789` where one allocation is excessive)
- [ ] [recommended] Heap or RSS growth at steady accepted throughput has been checked with the `performance` skill

## Standards and Reporting

- [ ] [recommended] Cross-tenant cache exposure is reported as `A01:2025` / ASVS V8, not merely performance
- [ ] [recommended] Unset platform limits are mapped to `A02:2025` / ASVS V13
- [ ] [recommended] Missing design bounds map to `A06:2025` / `API4:2023` / ASVS V4 or V15
- [ ] [recommended] Missing saturation telemetry maps to `A09:2025` / ASVS V16 where consequential
- [ ] [recommended] Failure amplification and skipped cleanup map to `A10:2025` / ASVS V16 where applicable
- [ ] [recommended] Only verified `CWE-400/401/770/772/789` identifiers are used
- [ ] [recommended] Every recommendation states security boundary, runtime cost, and when it should not be used

## Before Returning

- [ ] [critical] Runnable examples compile or execute with documented commands
- [ ] [recommended] Tests include saturation, two tenants, multiple replicas, N+1 count, and slow dependency as applicable
- [ ] [recommended] Observed values are separated from illustrative starting values
- [ ] [critical] Anything requiring deployed configuration or runtime evidence is labelled unverified
- [ ] [critical] No load test targets an unapproved system and no sensitive metric payload is retained
