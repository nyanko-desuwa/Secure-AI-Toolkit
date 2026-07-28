# Scalability Troubleshooting

Start with measurements. A single high RSS, queue, or replica count does not identify the failure.
Use a controlled workload only against an authorized environment.

## Measurement Sequence

1. Record deployment limits: maximum replicas, pool sizes, database limit, queue depth, cache cap,
   gateway body and rate limits, timeouts, and autoscaling rules.
2. Warm the service, then hold a steady offered rate for at least 10 minutes or five service-time
   windows. Record accepted/completed rate, p50/p95/p99 latency, errors, memory, CPU, queue age,
   in-flight work, dependency QPS, queries/request, pool wait, and replicas.
3. Repeat with cold cache and a burst at 2x the accepted steady rate. Confirm whether queues stabilize
   or grow. A stable warm cache is not evidence that arbitrary key input is safe.
4. Add one controlled fault: dependency latency at 2 seconds, connection refusal, or a slow client.
   Do not combine faults initially.
5. Compare the resource slope and the admitted work. A safe system rejects or degrades while memory,
   pool, downstream QPS, and replicas remain bounded.

Example load-tool shape, replace the placeholder with an authorized test URL:

```bash
# Only use against a system you own or are authorized to test.
hey -z 10m -c 40 -q 200 https://service.example.invalid/api/items?limit=50
```

Do not report a benchmark result without command, workload, duration, environment, and baseline.

## S1: In-Flight Work Rises Without Bound

Instrument a request counter around the dependency call. If it rises with offered rate while
latency rises, the semaphore is missing or placed after work creation. Check whether cancellation
actually aborts sockets and tasks. Compare total in-flight across replicas, not per-process values.

A safe first experiment is a per-dependency semaphore of 16 per replica, with a 100 ms acquisition
budget and a 2-second request deadline. This is not a universal value. Multiply by maximum replicas
and compare with the dependency quota before enabling it.

## S2: Queue or Memory Grows

Graph queue depth, oldest age, accepted rate, completion rate, item bytes, and RSS. If completion is
below admission, an unbounded queue will eventually fail. If depth is stable but RSS grows, inspect
retained payloads, buffers, listeners, and caches with `performance`.

Choose the full policy:

- Reject new public work with `503` and `Retry-After: 1`.
- Block only inside a bounded deadline when the caller can wait.
- Drop only disposable work and count every drop.
- Degrade to a smaller response or sampled event when the product permits it.

A larger queue changes delay, not sustainable throughput. State the memory budget using p99 item size.

## S3/S4: Cache Hit but Wrong or Stale Data

For two synthetic tenants, request the same resource ID in both orders after clearing the cache.
Log a redacted key fingerprint, tenant scope, representation, cache status, and origin authorization
result. Never log the value.

Check:

- Does the key include tenant and all response-varying authorization dimensions?
- Can an unauthorized or error response populate the entry?
- Is the cache shared across replicas or regions with different policy state?
- Is stale data acceptable for the endpoint, and for how many seconds?
- Are user-controlled dimensions canonicalized and bounded?

If the wrong tenant can read a value, disable the shared cache or bypass it for the endpoint before
attempting a key migration. Purge all old keys; changing code does not remove poisoned entries.

## S5: Rate Limit Differs by Replica

Send a known actor's requests through a load balancer while recording the replica identifier in an
internal test header or metric. Compare aggregate accepted requests to one limit window. If each
replica accepts the full allowance, the limiter is local or the key differs.

Verify the source of identity. A client-set forwarding header must never be accepted. Check the shared
store's atomic operation, clock/window behavior, TTL, fail-open decision, and regional routing. A
limiter outage that fails open on a costly operation is an A02/A06 design decision, not an invisible
availability detail.

## S6: Database Pool Exhaustion or N+1

Capture query count and normalized statements per request for page sizes 1, 10, and 100. A query count
of `1 + N` confirms N+1. Measure pool acquisition wait and connection hold duration separately.

If `pool_wait` rises while database CPU is low, look for connections held during serialization or
network calls. If database CPU is high, reduce queries and rows before increasing pool size. Compute:

```text
max connections from app = pool_max_per_replica × max_replicas
usable pool budget = database limit - admin/migration/other-service reserve
```

The first must be lower than the second. Check the effective running values; source configuration is
not deployment proof.

## S7: Autoscaling Makes an Outage Worse

Plot dependency latency, dependency QPS, total connections, queue age, replicas, and completed
requests on one timeline. If replicas and connections rise while completions fall, the scaling loop
is amplifying the outage.

Immediate containment: cap replicas, cap per-pod pool and in-flight work, open or manually trip the
circuit, and reject low-priority work. These are mitigations. Root cause is the missing dependency
budget or metric design. Restore capacity only after the dependency has headroom.

Check readiness and drain behavior. New pods that are marked ready before pools or warm caches are
safe add a cold-start wave; pods killed without drain may duplicate jobs or abandon transactions.

## S8: Retry Storm or Cache Stampede

Count attempts per logical request and distinguish client retries from service retries. If one
request has attempts at multiple layers, remove all but one retry owner. Plot attempt rate against
origin errors: a rising attempt-to-request ratio indicates amplification.

For cache expiry, graph misses and origin calls per key. If they spike at the same second, use jitter,
stale-while-revalidate where data permits, and bounded single-flight. Give locks an expiry so a
crashed owner cannot block a key forever. Remove stale lock entries and cap the lock map.

## When Measurements Conflict

- RSS grows while managed heap is flat: inspect native buffers, thread stacks, mapped files, and
  allocator retention. Use `performance`; do not add `gc.collect()` as a fix.
- CPU is low while latency is high: likely I/O wait, pool wait, queue wait, or a circuit/open state.
- Cache hit rate is high but latency is high: measure serialization, lock wait, cache network latency,
  and origin calls; hit rate alone is not capacity.
- Queue depth is zero but requests time out: work may be unbounded in promises, blocked on a pool, or
  rejected before queue metrics. Instrument each boundary.
- More replicas improve CPU but violate a dependency quota: cap replicas and redesign the bottleneck.
- A gateway reports a body or rate limit but direct internal routes bypass it: enforce at every
  allocation boundary and report the missing boundary.

## What Cannot Be Proven From Source

State unverified when you cannot inspect the running deployment:

- effective rate-limit store and clock semantics;
- proxy header stripping and route coverage;
- maximum replicas, pool sizes, cgroup memory, and database quotas;
- cache eviction, invalidation, and region consistency;
- autoscaler metric, stabilization, cooldown, and readiness behavior;
- whether alerts page an owner rather than merely display a graph.
