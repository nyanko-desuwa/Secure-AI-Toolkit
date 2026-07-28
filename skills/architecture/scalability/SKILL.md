---
name: scalability
description: 'Secure capacity, load shedding, backpressure, caching, rate limiting, database fan-out, and autoscaling. Use when reviewing growth, replicas, queues, caches, pools, or dependency protection. Triggers: "scalability", "autoscaling", "rate limit", "backpressure", "connection pool", "cache stampede", "horizontal scaling", "khả năng mở rộng", "giới hạn tải".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# Secure Scalability

Unbounded concurrency turns one slow dependency into exhausted pools. No backpressure turns a
throughput deficit into an out-of-memory kill. A shared cache accepts poisoned values or serves one
tenant's object to another. A process-local limiter grants its full allowance at every replica.
N+1 queries consume the database pool, and an autoscaler responds by opening still more connections
to the failing database. These are security failures before they are capacity problems.

This skill asks two questions for every scaling pattern:

1. Which security boundary does it create, preserve, or cross?
2. What does it cost at runtime under steady load and saturation?

## When to Use

- Adding replicas, workers, queues, caches, pools, batching, or autoscaling
- A service slows down as traffic rises or a dependency degrades
- Rate limits behave differently after horizontal scaling
- Cache entries cross tenants, remain stale after revocation, or can be filled by callers
- Database connections saturate, query count grows per result, or retries multiply load
- Choosing limits from measured traffic rather than framework defaults

## Failure-First Review

| Label | Failure | Boundary at risk | Runtime signature |
|---|---|---|---|
| S1 | Unbounded concurrency | Dependency availability | In-flight work and latency rise together |
| S2 | No backpressure | Public API to internal capacity | Queue depth or memory grows without bound |
| S3 | Shared cache poisoning | Origin to cache to caller | Untrusted response becomes shared state |
| S4 | Cross-tenant cache keys | Tenant authorization | Same object ID returns another tenant's value |
| S5 | Rate-limit bypass across replicas | Actor quota | Allowance multiplies by replica count |
| S6 | N+1 and pool exhaustion | Service to database | Queries/request rises with rows; pool wait spikes |
| S7 | Autoscaling amplifies outage | Service to dependency | More pods, more connections, less throughput |
| S8 | Retry and cache stampede | Service to dependency | Synchronized bursts after timeout or expiry |

Controls and runnable code: [best-practices.md](best-practices.md).

## Workflow

### 1. Draw capacity and trust boundaries

Name public callers, authenticated actors, tenants, replicas, queues, caches, pools, and downstream
services. A gateway is not the application boundary if internal routes bypass it. A cache is a
shared-data boundary. A queue is a capacity boundary only when bounded.

### 2. Measure one unit of work

Record queries, outbound calls, CPU time, allocated bytes, response bytes, and connection hold time
for one request. Repeat at p50 and p99 inputs. If cost grows with returned rows, nested fields, or
fan-out, state the function. Do not call a system scalable without this denominator.

### 3. Set a capacity envelope

Use measured service time and budgets:

```text
safe concurrency <= dependency capacity - reserved headroom
queue depth <= accepted wait / measured service time * worker count
pool budget per replica <= floor((database limit - reserve) / maximum replicas)
cache entries <= cache memory budget / measured p99 entry bytes
```

Every value needs a unit, source, owner, and alert threshold. Example values in this skill are
starting points, not production defaults.

### 4. Enforce the same identity at every replica

Rate-limit by verified actor after authentication and by a trusted client address only before it.
Use an atomic shared store or an edge service that all traffic traverses. Strip client-supplied
forwarding headers. Test the aggregate allowance while requests are distributed across replicas.

### 5. Bound, shed, and propagate pressure

Cap request size, fan-out, in-flight work, queue depth, pool acquisition, retries, and response size.
Choose what saturation means: reject, degrade, block for a short deadline, or drop disposable work.
Never choose unbounded buffering. Return `429` for actor quota and `503` with `Retry-After` for
transient service saturation.

### 6. Preserve cache authorization and integrity

Construct keys from tenant, authorization-relevant variation, resource ID, and representation
version. Cache only after origin validation and authorization. Do not share errors, redirects, or
responses containing user-specific data unless the key proves the correct scope. Bound size and age.

### 7. Protect dependencies from scaling

Divide database, HTTP, and broker budgets by maximum replicas, not current replicas. Apply bulkheads,
timeouts, circuit breakers, bounded retries, and minimum autoscaling stabilization. Scale on useful
work and saturation signals, not CPU alone. A dependency outage must reduce admitted work, not create
new callers.

### 8. Verify under saturation and failure

Run controlled load in a permitted test environment. Record offered rate, accepted rate, latency,
errors, queue depth, pool wait, queries/request, dependency calls/request, replica count, and memory.
Then make one dependency slow. Confirm rejection rises while queues, pools, memory, and replica count
remain within their budgets.

### 9. Report

For each finding provide label S1-S8, location, attacker or failure precondition, resource growth per
unit, hard limit, saturation behavior, security boundary, runtime cost of the fix, measurement or
missing measurement, and standards mapping.

## Standards Map

- `A01:2025` and ASVS V8: cross-tenant keys and authorization-sensitive caches.
- `A02:2025` and ASVS V13: unset pool, proxy, limiter, timeout, and autoscaling limits.
- `A06:2025`, `API4:2023`, ASVS V4/V15: missing resource budgets and unsafe scaling design.
- `A09:2025` and ASVS V16: no alert on queue, limiter, pool, cache, or shedding events.
- `A10:2025` and ASVS V16: retries, cleanup, and failure paths that amplify an outage.
- `CWE-400/770`: uncontrolled or unthrottled resource use.
- `CWE-401/772`: retained memory or resources after useful lifetime.
- `CWE-789`: one excessive input-derived allocation.

Use one precise CWE per finding where possible. Details: [references/standards-mapping.md](references/standards-mapping.md).

## When NOT to Use This

- Do not add a cache to a cold or authorization-sensitive path without a measured bottleneck. It adds
  stale authorization, invalidation, memory, and cross-tenant failure modes.
- Do not add a queue when the caller requires the result before success. A queue hides failure; it
  does not make the dependency optional.
- Do not add replicas when a shared database or paid API is already saturated. Replicas multiply
  connections and calls.
- Do not add a distributed limiter to a single-process internal job with a fixed input set. A local
  semaphore is cheaper and has no network dependency.
- Do not batch low-volume writes when added latency exceeds the saved calls or when partial failure
  cannot be reconciled.
- Do not split a small service merely to claim independent scaling. Each split adds a network trust
  boundary, timeout, retry path, pool, and deployment surface.
- Do not use autoscaling as outage recovery. Load shedding and dependency isolation must work while
  replica count is fixed.
- Do not optimize an unmeasured path. First remove unbounded work and leaks with the `performance`
  skill, then measure the remaining bottleneck.

## Related Skills

- `performance` — resource lifetime and heap diagnosis
- `event-driven` — broker trust, delivery, and consumer lifecycle
- `api-security` — API4, actor limits, GraphQL, and gateway headers
- `database-security` — query plans, tenant scoping, and database controls

## Supporting Files

- [README.md](README.md) — purpose, layout, use, limitations
- [checklist.md](checklist.md) — actionable pre-return checks
- [best-practices.md](best-practices.md) — S1-S8 patterns and code
- [common-mistakes.md](common-mistakes.md) — failure, cause, fix, reason
- [troubleshooting.md](troubleshooting.md) — diagnosis and conflicts
- [prompts.md](prompts.md) — prompts and anti-patterns
- [references/](references/) — concise verified standards and sizing notes
- [examples/README.md](examples/README.md) — runnable vulnerable/fixed pairs
