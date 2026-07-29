# Scalability Best Practices

The failure comes first. Every fixed pattern states the boundary it protects, its runtime cost, a
real initial limit, what to measure, and when not to use it. Example limits are hypotheses to verify.

## S1 - Bound Concurrency Before Creating Work

`A06:2025` · `API4:2023` · ASVS V15 · `CWE-400`, `CWE-770`

`Promise.all(ids.map(fetchOne))` creates all promises immediately. Ten thousand IDs become ten
thousand sockets, response buffers, and timers before a semaphore placed inside `fetchOne` can help.

```typescript
// Vulnerable: caller controls fan-out and all work starts at once.
export async function load(ids: string[]): Promise<unknown[]> {
  return Promise.all(ids.map((id) => fetch(`https://service.example/items/${id}`)
    .then((r) => r.json())));
}
```

```typescript
// Fixed: Node 20+, TypeScript. Work is created by 16 workers, not by ids.length tasks.
const MAX_ITEMS = 200;
const WORKERS = 16;
const PER_CALL_MS = 800;

export async function load(ids: string[]): Promise<unknown[]> {
  if (ids.length < 1 || ids.length > MAX_ITEMS) throw new RangeError("items must be 1..200");
  const output = new Array<unknown>(ids.length);
  let next = 0;

  async function worker(): Promise<void> {
    while (true) {
      const index = next++;
      if (index >= ids.length) return;
      const response = await fetch(`https://service.example/items/${encodeURIComponent(ids[index])}`, {
        signal: AbortSignal.timeout(PER_CALL_MS),
      });
      if (!response.ok) throw new Error(`upstream_${response.status}`);
      output[index] = await response.json();
    }
  }

  await Promise.all(Array.from({ length: Math.min(WORKERS, ids.length) }, worker));
  return output;
}
```

Security boundary: protects the downstream service from caller-controlled parallelism. Runtime cost:
at most 16 calls run; 200 items require at least 13 waves, so latency rises instead of connections.
Measure in-flight calls, p95 upstream service time, wait time, and timeouts. Start at 16 only when the
dependency budget supports `16 × maximum replicas`. Do not use fan-out at all when a bulk endpoint or
one database query can return the same data.

## S2 - Make Backpressure an API Outcome

`A06:2025` · `API4:2023` · ASVS V4/V15/V16 · `CWE-400`, `CWE-770`

An unbounded queue says every accepted request will finish while retaining bytes for work the system
cannot perform.

```python
# Vulnerable: maxsize=0 is unlimited; producer rate determines memory.
queue: asyncio.Queue[bytes] = asyncio.Queue()
await queue.put(request_body)
```

```python
# Fixed: Python 3.11. Reject before retaining beyond 2,000 bounded jobs.
import asyncio
from dataclasses import dataclass

MAX_BODY = 64 * 1024
QUEUE_DEPTH = 2_000
PUT_BUDGET = 0.025

@dataclass(frozen=True)
class Job:
    tenant_id: str
    body: bytes

queue: asyncio.Queue[Job] = asyncio.Queue(maxsize=QUEUE_DEPTH)

async def admit(tenant_id: str, body: bytes) -> None:
    if len(body) > MAX_BODY:
        raise ValueError("payload_too_large")
    try:
        await asyncio.wait_for(queue.put(Job(tenant_id, body)), timeout=PUT_BUDGET)
    except TimeoutError as error:
        raise RuntimeError("service_saturated_retry_after_1") from error
```

Security boundary: separates public demand from retained internal work. Runtime cost: worst-case
payload storage is roughly `2,000 × 64 KiB = 125 MiB` plus object overhead, which may already be too
large; measure actual p99 job bytes and choose a byte-aware queue when variation is high. Track depth,
age of oldest job, rejections, and process memory. Do not queue synchronous work whose result is
required before success; reject or process within the request deadline.

## S3/S4 - Cache Only Authorized, Canonical Representations

`A01:2025` · `A06:2025` · ASVS V8/V13/V15 · `CWE-401`, `CWE-770`

```typescript
// Vulnerable: tenant omitted; caller-controlled variant creates keys; errors can be cached.
const key = `invoice:${req.params.id}:${req.query.view}`;
const value = cache.get(key) ?? await origin(req.params.id, String(req.query.view));
cache.set(key, value);
```

```typescript
// Fixed: bounded key dimensions and population after scoped authorization.
type View = "summary" | "detail";
interface Actor { tenantId: string; permissions: Set<string> }
interface Invoice { id: string; tenantId: string; totalCents: number; lines: string[] }

const MAX_ENTRY_BYTES = 256 * 1024;
const ALLOWED_VIEWS = new Set<View>(["summary", "detail"]);

async function invoiceFor(actor: Actor, id: string, view: View): Promise<unknown> {
  if (!ALLOWED_VIEWS.has(view)) throw new Error("invalid_view");
  if (view === "detail" && !actor.permissions.has("invoice:detail")) throw new Error("not_found");
  const invoice = await db.findInvoice({ tenantId: actor.tenantId, id });
  if (!invoice) throw new Error("not_found");

  const key = `v3:tenant:${actor.tenantId}:invoice:${invoice.id}:view:${view}`;
  const hit = cache.get(key);
  if (hit !== undefined) return hit;
  const value = view === "summary"
    ? { id: invoice.id, totalCents: invoice.totalCents }
    : { id: invoice.id, totalCents: invoice.totalCents, lines: invoice.lines };
  const bytes = Buffer.byteLength(JSON.stringify(value));
  if (bytes <= MAX_ENTRY_BYTES) cache.set(key, value, { ttl: 60_000 });
  return value;
}
```

The cache implementation must also have a hard total byte or entry cap, such as 64 MiB and a
60-second TTL. Security boundary: tenant and permission-derived representation participate in both
authorization and key construction; unauthorized and error results do not populate shared state.
Runtime cost: lower hit rate and more key cardinality, plus serialization to measure entry size.
Measure hit rate by view, bytes, eviction, fill errors, and two-tenant negative tests. Do not use a
shared cache for rapidly revoked entitlements or secrets; a 60-second TTL is a 60-second stale window.

## S5 - Enforce One Rate Allowance Across Replicas

`A02:2025` · `A06:2025` · `API4:2023` · ASVS V4/V13/V15

A module-level counter grants `limit × replicas` and disappears on restart. A client-provided
`X-Forwarded-For` makes even that counter optional.

```python
# Vulnerable: each process grants 100; caller chooses forwarded identity.
key = request.headers.get("X-Forwarded-For", request.client.host)
hits[key] = hits.get(key, 0) + 1
if hits[key] > 100:
    raise TooManyRequests()
```

Use one atomic store traversed by all replicas. This Lua script is a fixed-window starting point:

```lua
-- KEYS[1] is built from a verified actor and operation; ARGV: limit, ttl_ms.
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
local ttl = redis.call('PTTL', KEYS[1])
if current > tonumber(ARGV[1]) then return {0, current, ttl} end
return {1, current, ttl}
```

Application key: `rl:v1:actor:{actor_id}:op:create-export:minute:{epoch_minute}`. The actor comes from
verified authentication. Pre-auth IP comes from a trusted proxy that removes incoming forwarding
headers. Security boundary: one principal receives one aggregate quota despite load balancing.
Runtime cost: one network round trip per decision and a Redis dependency. Pipeline independent
limits where semantics allow; keep a small local concurrency ceiling as fail-safe. Measure limiter
latency, 429s, fallback decisions, and aggregate requests accepted across replicas. Do not use a
distributed limiter for fixed-volume batch jobs; bound local workers instead.

## S6 - Make Query Count Independent of Row Count

`A06:2025` · `API4:2023` · ASVS V4/V15 · `CWE-400`, `CWE-772`

```python
# Vulnerable: 1 + N queries and a connection may be held while serialization runs.
orders = session.query(Order).limit(page_size).all()
return [{"id": o.id, "customer": session.get(Customer, o.customer_id).name} for o in orders]
```

```python
# Fixed: SQLAlchemy 2.x; server cap and batched relationship load.
from sqlalchemy import select
from sqlalchemy.orm import selectinload

MAX_PAGE = 100

def list_orders(session, tenant_id: str, requested: int):
    if requested < 1 or requested > MAX_PAGE:
        raise ValueError("page_size_must_be_1_to_100")
    stmt = (
        select(Order)
        .where(Order.tenant_id == tenant_id)
        .options(selectinload(Order.customer))
        .order_by(Order.id.desc())
        .limit(requested)
    )
    rows = session.scalars(stmt).all()
    return [{"id": row.id, "customer": row.customer.name} for row in rows]
```

Assert at most two queries for pages 1, 10, and 100. Security boundary: tenant scoping remains in the
query; eager loading must not load a relationship outside that scope. Runtime cost: two queries and
up to 100 related objects retained; a join can duplicate row bytes, while `selectinload` adds one
round trip. Pool formula: with a 300-connection database limit, 60 reserved, and 12 maximum replicas,
set at most `(300 - 60) / 12 = 20` connections per replica, then load-test acquisition time. Do not
eager-load large collections not used by the response.

## S7 - Put a Dependency Budget Ahead of Autoscaling

`A02:2025` · `A06:2025` · `A10:2025` · ASVS V13/V15/V16 · `CWE-400`

Bad loop: database latency raises request CPU and queue depth; autoscaler adds pods; each pod opens a
20-connection pool; the database receives more concurrent queries and slows further.

Fixed design:

```text
database limit             300 connections
operational reserve         60 connections
maximum application pods    12
pool maximum per pod        20 connections
per-pod DB in-flight        16 requests
pool acquisition deadline  100 ms
request total deadline       2 s
scale-up stabilization      60 s initial hypothesis
```

Reject before pool acquisition exceeds 100 ms. Open the circuit after a measured rolling failure
threshold and probe recovery with a small half-open allowance. Cap replicas at 12 until the database
budget changes. Scale on accepted queue age and useful completion rate, and alert when adding replicas
does not increase completions.

Security boundary: the service cannot consume the database's reserved administrative capacity.
Runtime cost: requests fail earlier with 503, and recovery probes may reject calls after the database
is healthy. Measure total connections, pool wait, completion rate, circuit state, replica count, and
DB latency. Do not autoscale a service whose bottleneck is a saturated singleton; shed load or raise
that dependency's capacity first.

## S8 - Bound Retries and Cache Fills

`A06:2025` · `A10:2025` · ASVS V15/V16 · `CWE-400`, `CWE-772`

```python
# Vulnerable: every layer retries three times; expiry causes every request to refill.
for _ in range(3):
    try:
        return await fetch_value(key)
    except Exception:
        pass
```

```python
# Fixed: one retry owner, total deadline, jitter, and one fill per key.
import asyncio, random, time

locks: dict[str, asyncio.Lock] = {}

async def get_value(key: str):
    if (value := cache.get(key)) is not None:
        return value
    lock = locks.setdefault(key, asyncio.Lock())
    try:
        async with asyncio.timeout(1.0):
            async with lock:
                if (value := cache.get(key)) is not None:
                    return value
                deadline = time.monotonic() + 0.8
                for attempt in range(2):
                    try:
                        value = await fetch_value(key, timeout=min(0.35, deadline - time.monotonic()))
                        cache.set(key, value, ttl=55 + random.random() * 10)
                        return value
                    except TransientError:
                        if attempt == 1 or time.monotonic() >= deadline:
                            raise
                        await asyncio.sleep(random.uniform(0.02, 0.08))
    finally:
        if not lock.locked():
            locks.pop(key, None)
```

The lock map itself needs cleanup and a maximum key count in production; a bounded single-flight
library is safer. Security boundary: caller bursts cannot multiply origin calls for one key. Runtime
cost: same-key callers wait and may time out; jitter lowers synchronized expiry but makes freshness
nonuniform. Measure origin calls per cache miss, fill wait, lock cardinality, retries, and stale
serves. Do not serve stale authorization or revocation data merely to preserve availability.

## Measurement Contract

For every claimed improvement report this row:

| Field | Example |
|---|---|
| Workload | 200 requests/s for 15 minutes, 5% requests with 100 items |
| Baseline | p95 1.8 s; 420 downstream in-flight; 8% timeout |
| Change | fan-out workers 16, item cap 200, call timeout 800 ms |
| Result | p95 620 ms; in-flight <= 192 across 12 pods; 1.1% 503 |
| Boundary | downstream allowance held below 200 concurrent calls |
| Cost | 503 under bursts; largest batches complete in waves |

Without these measurements, describe the control as an unverified initial configuration, not an
optimization result.
