# Scalability Prompt Examples

Prompts should name the boundary, workload, resource, and evidence required. The S1-S8 labels are
in [SKILL.md](SKILL.md).

## Review a fan-out endpoint

```text
Review src/api/export.ts with skills/architecture/scalability. Find every input that controls item
count, promises, outbound calls, response bytes, or elapsed time. Give the vulnerable and fixed
TypeScript pair, a server-side limit with units, the dependency budget across 12 replicas, saturation
response, security boundary, runtime cost, and the measurement that would validate it. Label S1.
```

## Diagnose no backpressure

```text
Our Python ingest accepts 400 events/s and workers complete 250/s. RSS grows 30 MiB/hour and the
asyncio queue has no maxsize. Use the troubleshooting method. Compare reject, bounded wait, and drop;
calculate an initial queue depth from a 2-second wait budget and the measured p99 event size; map the
finding to API4:2023 and CWE-770/400. Do not recommend simply raising the queue.
```

## Audit a shared cache

```text
Read src/cache and the tenant-scoped handlers. For each key, list tenant, actor, representation,
locale, and policy dimensions. Trace whether unauthorized, error, or unvalidated upstream responses
can populate it. Provide a two-tenant test, byte and entry limits, TTL/revocation window, hit-rate
and eviction metrics, and the cost of bypassing the cache. Treat a cross-tenant hit as A01:2025 and
ASVS V8. Label S3/S4.
```

## Test replica-wide rate limits

```text
Review the limiter and deployment config. Tell me whether 10 replicas share one atomic allowance,
what identity is trusted before and after authentication, and whether client-set forwarding headers
are stripped. Give a test that sends a known actor through every replica and reports aggregate accepted
requests, store latency, fallback behavior, and key cardinality. Map missing limits to A02/A06, API4,
and ASVS V4/V13. Label S5.
```

## Find N+1 and pool exhaustion

```text
Review the list endpoint and ORM calls. Run or design a query-count test at page sizes 1, 10, and 100.
Identify N+1, result-set caps, tenant scope, transaction/network overlap, pool wait, and connection
arithmetic for 300 database connections, 60 reserved, and 12 maximum replicas. Give a fixed Python
pair and its memory/query/latency cost. Label S6.
```

## Challenge autoscaling

```text
A database slows from 100 ms to 2 s; the service autoscaler increases from 4 to 30 pods and the
outage worsens. Build a timeline using dependency latency, QPS, connections, pool wait, queue age,
replicas, and completed requests. Propose a capped budget, stabilization behavior, load shedding,
and a slow-dependency test. Distinguish A02 misconfiguration from A06 design. Label S7.
```

## Audit retries and stampedes

```text
Trace one logical request through client, gateway, service, SDK, and cache fill. Count maximum
attempts and total time, classify retryable errors, verify idempotency, jitter, circuit state, lock
expiry, and lock-map cleanup. Show how a five-layer three-attempt design reaches 243 possible calls.
Give the smallest fixed policy and its runtime cost. Label S8.
```

## Decide whether to add a cache or queue

```text
Do not recommend a pattern yet. Compare the measured bottleneck with a direct call, bounded cache,
bulk endpoint, bounded queue, and no change. For each state security boundary, staleness or delay,
retained bytes, dependency cost, failure behavior, observability, and when NOT to use it. Reject any
option whose limit or owner cannot be named.
```

## Verify a change before return

```text
Run checklist.md against this change. Mark pass, fail, or not applicable with a reason. Do not mark
gateway limits, proxy trust, deployed autoscaling, cache eviction, database quotas, or alerts pass
without runtime evidence. Report line-level findings with S label, standards, limit basis, security
boundary, runtime cost, residual gap, and tests run.
```

## Anti-patterns

| Prompt | Why it fails | Better request |
|---|---|---|
| "Make it scalable" | No workload, resource, or target | Name p99, offered rate, dependency, and budget |
| "Add caching" | Creates S3/S4 without key or expiry | Ask which measured call is slow and bound key, bytes, TTL |
| "Add a queue" | Hides overload in retained memory | Ask max depth, bytes, full behavior, and caller semantics |
| "Add rate limiting" | Misses actor, operation, replicas, and proxy trust | Test aggregate allowance across replicas |
| "Increase the pool" | Can exhaust the database faster | Do connection arithmetic at maximum replicas |
| "Add retries" | Creates multiplicative outage load | One retry owner, deadline, cap, jitter, idempotency |
| "Turn on autoscaling" | A control loop can amplify dependency failure | Scale on useful work with downstream caps |
| "Use UUIDs for security" | Obscurity does not authorize access | Scope every lookup by tenant/actor policy |
| "Warm every cache" | Cold-start burst and stale/private data | Warm only measured, non-sensitive keys with a budget |
| "Optimize without measuring" | Adds indirection and hides the real bottleneck | Define baseline, workload, metric, and result |
