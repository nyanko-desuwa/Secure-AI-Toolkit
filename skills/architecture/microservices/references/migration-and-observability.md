# Migration and Observable Limits

Verified 2026-07-28. Values below are fields to define and measure, not universal defaults.

## Reversible extraction

| Phase | Security gate | Runtime gate | Rollback requirement |
|---|---|---|---|
| Contract | Owner and object policy defined | Deadline and payload bound | Old reader accepts expanded form |
| Observe | Deny events and audit path visible | Baseline pool, latency, queue, trace cost | No mutation in shadow path |
| Backfill | Least-privilege migration identity | Batch, concurrency, checkpoint bounds | Resume and reconcile by key |
| Cohort | Same owner policy on both paths | Error, p99, pool wait, divergence limits | Route cohort back immediately |
| Cutover | New owner is authoritative | Capacity and dependency budget verified | Accepted new writes reconciled |
| Contract | Legacy privilege removed | Compatibility state expires | Rollback window explicitly closed |

Avoid indefinite dual writes. Prefer one authority with an outbox, CDC, or bounded compatibility route. Reconciliation needs an owner, a query, an interval, and a stopping threshold.

## Observable limits

| Resource | Configuration | Signals | Saturation behavior |
|---|---|---|---|
| Request | total deadline and per-hop timeouts | latency, timeout reason | fail or degrade explicitly |
| Retry | max attempts and shared budget | attempts/original, exhausted | stop, do not loop |
| Fan-out | max dependencies and concurrency | width, partial failures | reject or return partial result |
| Pool | max/idle/lifetime/wait | in-use, idle, waiters, wait time | time out before upstream deadline |
| Queue | items, bytes, max age, DLQ retention | depth, bytes, oldest, rates | block, reject, or shed by policy |
| Saga | active count, context bytes, expiry | count, oldest, compensation failures | expire to owned recovery path |
| Trace | sampling, spans, attribute length, exporter queue | emitted/dropped/exporter lag | sample/drop without blocking request |
| Breaker | finite dependency keys and eviction | key count, state transitions | reject with bounded state |
| Cache | entries/bytes/TTL | size, evictions, stale-policy age | evict or reject allocation |

## API inventory fields

Record protocol, method/path/topic, version, owner, audience, workload authentication, subject propagation, object authorization, tenant scope, data classification, request/response size, rate/concurrency limit, deadline, retries, idempotency, dependencies, events, telemetry, and deprecation date. Generate candidates from code and deployment configuration, then verify live reachability; neither source nor an API gateway catalog alone is complete.

## Limitations

- Declared limits may be overridden by mesh, ingress, runtime, broker, database, or environment configuration.
- Dashboards can be missing labels, sampled, delayed, or high-cardinality; they do not prove absence.
- A rollback test without writes does not verify write reconciliation.
- Resource math gives an upper bound only if maximum replicas and all client pools are known.

## Sources

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/> (A06, A09, A10; pinned 2026-07-28).
- OWASP ASVS 5.0.0 — <https://owasp.org/www-project-application-security-verification-standard/> (V4, V13, V15, V16; pinned 2026-07-28).
- Resource-lifecycle depth — `skills/architecture/performance/`.
- Event migration and queue detail — `skills/architecture/event-driven/`.
