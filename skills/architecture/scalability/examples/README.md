# Scalability Examples

Eight runnable vulnerable/fixed pairs. TypeScript examples require Node 20 and run with
`npx tsx file.ts`. Python examples require Python 3.11 and use only the standard library unless
noted. Each pair names its boundary and runtime cost. Do not copy a block labelled `Vulnerable:`.

## 1. Unbounded Concurrency

`S1` · `A06:2025` · `API4:2023` · `CWE-770`

```typescript
// Vulnerable: concurrency-vulnerable.ts
let inFlight = 0;
async function work(id: number): Promise<number> {
  inFlight += 1;
  await new Promise((resolve) => setTimeout(resolve, 10));
  inFlight -= 1;
  return id;
}
async function main(): Promise<void> {
  let peak = 0;
  const timer = setInterval(() => { peak = Math.max(peak, inFlight); }, 1);
  await Promise.all(Array.from({ length: 1000 }, (_, id) => work(id)));
  clearInterval(timer);
  console.log({ peak });
}
void main();
```

```typescript
// Fixed: concurrency-fixed.ts
let inFlight = 0;
let peak = 0;
const WORKERS = 16;
async function work(id: number): Promise<number> {
  inFlight += 1; peak = Math.max(peak, inFlight);
  await new Promise((resolve) => setTimeout(resolve, 10));
  inFlight -= 1;
  return id;
}
async function main(): Promise<void> {
  const ids = Array.from({ length: 200 }, (_, id) => id);
  const results = new Array<number>(ids.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < ids.length) { const i = next++; results[i] = await work(ids[i]); }
  }
  await Promise.all(Array.from({ length: WORKERS }, worker));
  console.log({ peak, completed: results.length });
}
void main();
```

Boundary: dependency concurrency. Cost: peak is 16, while completion takes multiple waves. A 200-item
cap is concrete but must be justified from the dependency and request deadline. Do not use fan-out if
a bulk call exists.

## 2. No Backpressure

`S2` · `A06:2025` · `API4:2023` · `CWE-400`, `CWE-770`

```python
# Vulnerable: queue_vulnerable.py
import asyncio

async def main() -> None:
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    for _ in range(100_000):
        queue.put_nowait(b"x" * 1024)
    print(queue.qsize())  # about 100 MiB of payload retained

asyncio.run(main())
```

```python
# Fixed: queue_fixed.py
import asyncio

MAX_BODY = 64 * 1024
queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1000)

async def admit(body: bytes) -> bool:
    if len(body) > MAX_BODY:
        return False
    try:
        await asyncio.wait_for(queue.put(body), timeout=0.025)
        return True
    except TimeoutError:
        return False

async def main() -> None:
    accepted = sum([await admit(b"x" * 1024) for _ in range(1001)])
    print({"accepted": accepted, "rejected": 1001 - accepted, "depth": queue.qsize()})

asyncio.run(main())
```

Boundary: admission to retained work. Cost: the 1001st job waits up to 25 ms then fails. The queue
still permits about 62.5 MiB at maximum item size, so measure p99 bytes. Do not queue synchronous work.

## 3. Shared Cache Poisoning

`S3` · `A06:2025` · ASVS V15 · `CWE-770`

```typescript
// Vulnerable: poison-vulnerable.ts
const cache = new Map<string, { status: number; body: string }>();
function proxy(path: string, originStatus: number, originBody: string) {
  const hit = cache.get(path);
  if (hit) return hit;
  const response = { status: originStatus, body: originBody };
  cache.set(path, response); // caches errors and caller-chosen key space
  return response;
}
console.log(proxy("/catalog?format=anything", 503, "temporary failure"));
console.log(proxy("/catalog?format=anything", 200, "healthy")); // still 503
```

```typescript
// Fixed: poison-fixed.ts
type Format = "compact" | "full";
const cache = new Map<string, { expires: number; body: string }>();
const MAX_ENTRIES = 1000;
function proxy(format: Format, originStatus: number, originBody: string): string {
  const key = `catalog:v2:${format}`;
  const hit = cache.get(key);
  if (hit && hit.expires > Date.now()) return hit.body;
  if (originStatus !== 200 || Buffer.byteLength(originBody) > 256 * 1024) {
    throw new Error(`origin_${originStatus}`);
  }
  if (cache.size >= MAX_ENTRIES) cache.delete(cache.keys().next().value!);
  cache.set(key, { expires: Date.now() + 30_000, body: originBody });
  return originBody;
}
console.log(proxy("compact", 200, "healthy"));
```

Boundary: origin response to shared state. Cost: validation, 256 KiB item cap, eviction, and origin
calls during failures. Do not cache arbitrary error or redirect responses.

## 4. Cross-Tenant Cache Key

`S4` · `A01:2025` · ASVS V8 · `CWE-401`

```python
# Vulnerable: tenant_cache_vulnerable.py
cache: dict[str, str] = {}

def get_invoice(tenant: str, invoice_id: str) -> str:
    key = f"invoice:{invoice_id}"
    if key not in cache:
        cache[key] = f"private data for {tenant}"
    return cache[key]

print(get_invoice("tenant-a", "42"))
print(get_invoice("tenant-b", "42"))  # tenant-a data
```

```python
# Fixed: tenant_cache_fixed.py
from time import monotonic

cache: dict[str, tuple[float, str]] = {}
TTL = 60.0
MAX_ENTRIES = 1000

def get_invoice(tenant: str, invoice_id: str) -> str:
    key = f"v2:tenant:{tenant}:invoice:{invoice_id}"
    now = monotonic()
    hit = cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    value = f"private data for {tenant}"  # production origin query is tenant-scoped
    if len(cache) >= MAX_ENTRIES:
        cache.pop(next(iter(cache)))
    cache[key] = (now + TTL, value)
    return value

print(get_invoice("tenant-a", "42"))
print(get_invoice("tenant-b", "42"))
```

Boundary: tenant authorization. Cost: duplicate entries and lower hit rate; TTL is a 60-second stale
window. Do not cache permission decisions where revocation must be immediate.

## 5. Per-Replica Rate-Limit Bypass

`S5` · `A02:2025` · `API4:2023` · ASVS V4/V13

```python
# Vulnerable: limiter_vulnerable.py
class Replica:
    def __init__(self) -> None: self.hits: dict[str, int] = {}
    def allow(self, actor: str) -> bool:
        self.hits[actor] = self.hits.get(actor, 0) + 1
        return self.hits[actor] <= 3

replicas = [Replica(), Replica()]
print(sum(replicas[i % 2].allow("actor-1") for i in range(6)))  # 6, not 3
```

```python
# Fixed: limiter_fixed.py
import threading

class AtomicStore:
    def __init__(self) -> None:
        self.lock = threading.Lock(); self.hits: dict[str, int] = {}
    def increment_and_allow(self, key: str, limit: int) -> bool:
        with self.lock:
            self.hits[key] = self.hits.get(key, 0) + 1
            return self.hits[key] <= limit

store = AtomicStore()
def allow(verified_actor: str) -> bool:
    return store.increment_and_allow(f"rl:v1:create:{verified_actor}:minute-0", 3)
print(sum(allow("actor-1") for _ in range(6)))  # 3
```

The in-process `AtomicStore` demonstrates shared atomic semantics in one runnable script; production
replicas need Redis or an enforced edge with expiry. Boundary: actor quota. Cost: one shared decision
per request. Do not trust caller-supplied forwarding or actor headers.

## 6. N+1 and Connection Pressure

`S6` · `A06:2025` · `API4:2023` · `CWE-400`, `CWE-772`

```python
# Vulnerable: nplus1_vulnerable.py
import sqlite3
conn = sqlite3.connect(":memory:")
conn.executescript("CREATE TABLE customer(id INTEGER PRIMARY KEY,name TEXT); CREATE TABLE orders(id INTEGER,customer_id INTEGER); INSERT INTO customer VALUES(1,'A'),(2,'B'); INSERT INTO orders VALUES(10,1),(11,2);")
queries = 1
rows = conn.execute("SELECT id,customer_id FROM orders").fetchall()
for order_id, customer_id in rows:
    queries += 1
    name = conn.execute("SELECT name FROM customer WHERE id=?", (customer_id,)).fetchone()[0]
    print(order_id, name)
print({"queries": queries})
```

```python
# Fixed: nplus1_fixed.py
import sqlite3
conn = sqlite3.connect(":memory:")
conn.executescript("CREATE TABLE customer(id INTEGER PRIMARY KEY,name TEXT); CREATE TABLE orders(id INTEGER,customer_id INTEGER); INSERT INTO customer VALUES(1,'A'),(2,'B'); INSERT INTO orders VALUES(10,1),(11,2);")
MAX_PAGE = 100
requested = 100
if not 1 <= requested <= MAX_PAGE: raise ValueError("invalid_page")
rows = conn.execute("SELECT o.id,c.name FROM orders o JOIN customer c ON c.id=o.customer_id ORDER BY o.id LIMIT ?", (requested,)).fetchall()
print(rows)
print({"queries": 1})
```

Boundary: application to database, with tenant scoping required in production SQL. Cost: joins can
repeat customer bytes; page cap retains at most 100 rows. Assert query count does not grow with page.
Do not raise pool size before removing N+1.

## 7. Autoscaling Amplifies a Dependency Outage

`S7` · `A02:2025` · `A06:2025` · `A10:2025` · `CWE-400`

```python
# Vulnerable: autoscale_vulnerable.py
pods, pool_per_pod, db_limit = 4, 20, 300
for latency_seconds in (0.1, 0.5, 1.0, 2.0):
    if latency_seconds > 0.2: pods += 10
    print({"latency": latency_seconds, "pods": pods,
           "possible_connections": pods * pool_per_pod, "db_limit": db_limit})
```

```python
# Fixed: autoscale_fixed.py
DB_LIMIT, RESERVE, MAX_PODS = 300, 60, 12
POOL_PER_POD = (DB_LIMIT - RESERVE) // MAX_PODS  # 20
pods = 4
for latency_seconds in (0.1, 0.5, 1.0, 2.0):
    dependency_healthy = latency_seconds <= 0.2
    if dependency_healthy: pods = min(MAX_PODS, pods + 1)
    admitted_per_pod = 16 if dependency_healthy else 2
    print({"latency": latency_seconds, "pods": pods,
           "connection_ceiling": pods * POOL_PER_POD,
           "admitted": pods * admitted_per_pod})
```

Boundary: database capacity reserve. Cost: unhealthy service sheds work instead of scaling, so 503
rises. Measure useful completions; this script illustrates arithmetic, not an autoscaler API. Do not
scale past a saturated singleton.

## 8. Retry and Stampede Amplification

`S8` · `A06:2025` · `A10:2025` · `CWE-400`

```typescript
// Vulnerable: retry-vulnerable.ts
let calls = 0;
async function origin(): Promise<string> { calls += 1; throw new Error("down"); }
async function layer(fn: () => Promise<string>): Promise<string> {
  let last: unknown;
  for (let i = 0; i < 3; i += 1) try { return await fn(); } catch (e) { last = e; }
  throw last;
}
void layer(() => layer(() => layer(origin))).catch(() => console.log({ calls })); // 27
```

```typescript
// Fixed: retry-fixed.ts
let calls = 0;
async function origin(): Promise<string> { calls += 1; throw new Error("down"); }
async function withRetry(): Promise<string> {
  let last: unknown;
  const deadline = Date.now() + 300;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try { return await origin(); } catch (error) { last = error; }
    if (Date.now() >= deadline || attempt === 1) break;
    await new Promise((r) => setTimeout(r, 20 + Math.random() * 30));
  }
  throw last;
}
void withRetry().catch(() => console.log({ calls })); // 2
```

Boundary: service to failing dependency. Cost: only two chances to recover, with added jitter delay.
Production retries only classified transient, idempotent operations and uses one total deadline. Do
not retry non-idempotent writes without a stable idempotency key.

## Measurements to Record

For each pair record offered/accepted/completed rate, p95/p99 latency, errors, in-flight count, queue
age, cache bytes/hits/evictions, queries/request, pool wait, dependency QPS, retries/logical request,
replica count, RSS, and the hard ceiling. Values without workload and duration are not evidence.
