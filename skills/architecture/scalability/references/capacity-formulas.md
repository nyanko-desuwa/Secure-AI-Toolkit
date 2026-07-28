# Capacity Formulas

These formulas convert measurements into limits. They are starting calculations, not guarantees.
Use p99 service time, burst duration, dependency quota, and reserved headroom from the real system.

## Concurrency

```text
Little's Law: in-flight work ≈ arrival rate × average service time
safe dependency concurrency = dependency quota - reserve
per-replica concurrency <= floor(safe dependency concurrency / maximum replicas)
```

Example: a provider permits 240 concurrent calls, 48 are reserved, and 12 pods may run. A starting
per-pod ceiling is `floor((240 - 48) / 12) = 16`. The reserve covers health, admin, and variance.
Measure actual p99 latency and rejected calls before changing it.

## Queue Depth

```text
queue items <= workers × (accepted wait budget / p99 service time)
queue bytes <= item count × measured p99 item bytes
```

Example: four workers, 2 seconds accepted wait, and 250 ms p99 service time yield 32 items. If p99
item size is 20 KiB, 32 items retain about 640 KiB, excluding overhead. A 2,000-item queue would
represent 40 MiB at that same p99 and a much longer wait. Burst tolerance and fairness may justify a
different value; measure oldest age.

## Database Connections

```text
app connection ceiling = pool max per replica × maximum replicas
usable budget = database connection limit - migrations - admin - other services - reserve
```

Example: limit 300, reserve and other use 60, maximum 12 replicas gives 20 connections per replica.
If background workers also use 24, reduce the application budget before setting pool max. A pool
value in source is not proof of the effective running value.

## Cache Memory

```text
max entries <= cache byte budget / p99 serialized entry bytes
```

Example: a 64 MiB budget and 4 KiB p99 serialized value gives a theoretical 16,384 entries before
key, index, allocator, and overhead. Use a lower cap such as 10,000 until overhead is measured. Bound
both entry size and total bytes; a count alone is unsafe when values vary.

## Rate Limits

A fixed window of 100 requests/minute permits a burst of 100 at the boundary. A token bucket has a
separate burst capacity and refill rate. Choose from product and dependency budgets, then test across
replicas. The aggregate actor allowance must not multiply by replica count.

## Retry Amplification

```text
maximum attempts = product of attempts at every retrying layer
```

Three attempts at four layers can produce `3^4 = 81` downstream calls per logical request. Choose one
retry owner and a total deadline. Backoff with jitter changes timing, not the maximum; the attempt cap
still matters. Never retry a non-idempotent write without a stable idempotency key.

## Autoscaling Ceiling

```text
max replicas <= floor((dependency quota - reserve) / per-replica maximum demand)
```

The tightest dependency wins: database connections, provider QPS, broker partitions, memory, or paid
quota. Scale on useful completions and queue age, then stabilize scale-up so a failure does not cause
a rapid cold-start wave. A maximum replica setting is a safety bound, not proof that the chosen value
is safe.

## Measurement Record

For each formula record input values, units, date, environment, p50/p99 source, and owner. Report
accepted rate, completion rate, latency, queue age, in-flight work, dependency calls, pool wait,
replicas, memory, and errors before and after. If a value is illustrative, label it so.
