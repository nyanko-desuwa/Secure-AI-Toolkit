# Scalability Common Mistakes

Each mistake states what fails, why, the fix, why it holds, the boundary, and its cost.

## `Promise.all` used as a scheduler

What fails: every input starts work immediately. A 10,000-item request creates 10,000 promises and
outbound calls. The caller controls dependency concurrency (`A06:2025`, `API4`, `CWE-770`).

Fix: reject above a server-side item cap and create work through a fixed worker pool or semaphore.
Why it holds: work does not exist before capacity is available. Boundary: service to dependency.
Cost: large batches take waves and may time out. Prefer a bulk dependency operation when available.

## Bounded queue, unbounded payload

What fails: `Queue(maxsize=1000)` looks safe, but each item may be a 50 MiB body. One large allocation
can be `CWE-789`; total retained bytes become `CWE-770`.

Fix: bound bytes before enqueue, bound item count, and use a byte-aware admission budget. Why it
holds: both dimensions have ceilings. Cost: size accounting and 413/503 responses.

## Removing backpressure because it caused 503s

What fails: rejection was the evidence that offered work exceeded capacity. Removing the limit
changes visible 503s into latency, memory growth, then OOM.

Fix: keep the bound, measure accepted versus completed rate, reduce work, add safe capacity, or shed
lower-priority traffic. Boundary: public demand to internal capacity. Cost: clients must retry with
jitter or accept degraded output.

## Cache key omits tenant

```text
invoice:{invoice_id}                    vulnerable
v3:tenant:{tenant_id}:invoice:{id}      fixed baseline
```

What fails: the first tenant to populate an ID serves its object to another. Report `A01:2025` and
ASVS V8, not a performance defect.

Fix: authorize the origin read and include tenant plus representation dimensions in the key. Why it
holds: values from distinct policy scopes cannot collide. Cost: lower hit rate and more entries.
Never share rapidly revoked authorization decisions.

## Cache key includes raw attacker input

What fails: query strings, headers, or arbitrary JSON generate unbounded unique keys. A cache becomes
attacker-driven retained memory (`CWE-401`, `CWE-770`).

Fix: parse to a closed schema, canonicalize, reject unknown dimensions, cap total bytes and entry
size, then hash only the canonical form if key length matters. Why it holds: key cardinality follows
server-chosen dimensions. Cost: validation and serialization CPU.

## Caching errors and redirects with successful data

What fails: a transient 500, malicious upstream redirect, or unauthorized 404 can poison shared
state. Extending TTL makes the outage durable.

Fix: cache an explicit allowlist of status and content types only after validation; use short bounded
negative caching only for domain-safe not-found results. Why it holds: exceptional responses never
become shared truth. Cost: more origin load during failures.

## Process-local rate limiting after adding replicas

What fails: each replica grants its own allowance, so effective quota is `N × limit`. Restarts erase
counters and load balancing becomes a bypass.

Fix: atomic shared counters or one enforced edge, keyed by verified actor and operation. Verify by
sending ordinary test traffic through every replica. Why it holds: there is one decision state.
Cost: network latency and a limiter dependency. Keep local concurrency shedding for limiter failure.

## Trusting `X-Forwarded-For`

What fails: a caller sets a new header value per request and bypasses IP controls. This is also an
ASVS V4 intermediary-header concern.

Fix: the trusted edge removes incoming copies, appends its observed peer, and the application trusts
only a configured proxy chain. Why it holds: identity is established outside caller-controlled data.
Cost: proxy configuration and tests; direct application access must be blocked or handled separately.

## N+1 fixed by raising pool size

What fails: one request still performs `1 + N` queries, but can now consume more database concurrency.
At many replicas, `pool × replicas` exceeds the database limit.

Fix: batch or eager-load, cap rows, assert query count, and divide pool budget by maximum replicas.
Why it holds: calls/request stays constant and total connections have a ceiling. Cost: joins can
increase returned bytes and eager loads retain more objects.

## Pool created per request

What fails: each request creates connections and drops their owner. Error paths retain scarce
resources (`CWE-772`) and the database reaches its connection limit.

Fix: one process-owned bounded pool, short acquisition deadline, scoped acquire, and shutdown close.
Why it holds: resource ownership and maximum lifetime are explicit. Cost: saturated requests wait
briefly or fail instead of opening more connections.

## Holding a transaction across an HTTP call

What fails: a slow dependency holds database connections and locks. Autoscaling adds callers and
exhausts the pool.

Fix: commit local intent, call downstream outside the transaction with an idempotency key, then
reconcile. Why it holds: network time no longer consumes the transaction budget. Cost: requires an
outbox/state machine and handles partial outcomes.

## Retrying at every layer

What fails: client, gateway, service, and SDK each retry three times, creating up to `3^4 = 81`
attempts for one operation. Fixed-delay retries synchronize callers.

Fix: one retry owner, at most two or three classified transient attempts inside one total deadline,
with exponential backoff and jitter. Why it holds: amplification is arithmetically bounded. Cost:
fewer requests recover from long transient failures; idempotency is required.

## Circuit breaker with no local concurrency bound

What fails: the breaker opens only after failures. Before that, thousands of calls are already in
flight. Half-open recovery can also flood the dependency.

Fix: combine semaphore, timeout, breaker, and a small half-open probe count. Why it holds: concurrency
is bounded before failure detection. Cost: healthy traffic can queue behind the bulkhead.

## Autoscaling on CPU alone

What fails: blocked I/O may use little CPU while queues and pool wait explode; retry loops may use
high CPU and trigger more replicas against a failing dependency.

Fix: include useful completion rate, queue age, pool wait, and dependency saturation; cap replicas by
downstream budgets and stabilize scale-up. Why it holds: the control loop observes capacity, not
activity. Cost: more metrics and slower reaction to genuine bursts.

## Maximum replicas without connection arithmetic

What fails: `20 pool connections × 50 pods = 1,000` against a 300-connection database.

Fix: reserve operational headroom, then divide the remainder by configured maximum pods. Revisit both
values together. Why it holds: scale-out cannot exceed the global pool budget. Cost: small per-pod
pools may reject before CPU is busy.

## Caching used to conceal an expensive authorization query

What fails: a long TTL improves latency while revoked access remains valid. A shared key can expose
another tenant. The security boundary moved into cache configuration nobody reviewed.

Fix: optimize and index the authorization query first. If caching remains necessary, key by policy
scope, use a short TTL or explicit invalidation, and state the revocation window. Cost: lower hit rate
and invalidation traffic. Do not use when immediate revocation is required.

## Larger instance or restart called a fix

What fails: both delay the same slope. A restart may also drop queues and in-flight work.

Fix: name growth per request, bound it, and use the `performance` skill to find retained objects.
Why it holds: it changes the slope or ceiling rather than resetting the clock. Cost: proper diagnosis
needs steady-load measurements and profiles.

## Benchmarked only on the happy path

What fails: a design appears scalable while all caches are warm and dependencies are healthy.

Fix: measure cold cache, burst, slow client, full queue, database latency, timeout, and one failed
dependency. Why it holds: failure amplification becomes visible before production. Cost: a longer,
controlled test matrix; never direct it at an unapproved system.
