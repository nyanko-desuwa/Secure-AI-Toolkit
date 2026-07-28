# Performance Best Practices

Resource lifetime patterns, in the order they cause outages. Each names the OWASP category,
the ASVS chapter, and the CWE it serves. Leak prevention comes first; throughput follows.

## Bounds Are the Control

`A06:2025` · `API4:2023` · ASVS V2, V13 · `CWE-770`

Anything sized by input needs an explicit maximum. A missing bound is a finding on its own.

| Acquisition | Bound it needs |
|---|---|
| Cache | max entries or bytes, plus TTL |
| Queue | max depth; choose block, drop, or reject when full |
| Request / result | max bytes or records, enforced server-side |
| Pool / concurrency | max size, acquire timeout, cancellation |
| Retry / task | attempt and time budget, cancellation owner |

"Silently grow" is not a full-queue policy. It is what happens when nobody chose.

## L1 — Unbounded Cache

`A06:2025` · `CWE-401`, `CWE-770`

A dict keyed by anything the caller controls is a memory leak with a cache-shaped name.

```python
# Vulnerable: one entry per distinct query string, forever
_render_cache: dict[str, str] = {}

def render(template_key: str, params: str) -> str:
    key = f"{template_key}:{params}"
    if key not in _render_cache:
        _render_cache[key] = expensive_render(template_key, params)
    return _render_cache[key]
```

```python
# Fixed: bounded entries, bounded age, bounded key space
from cachetools import TTLCache
import threading

MAX_ENTRIES = 10_000  # ~40 MB at an observed p99 entry of 4 KB
_cache: TTLCache[str, str] = TTLCache(maxsize=MAX_ENTRIES, ttl=300)
_lock = threading.Lock()  # cachetools is not thread-safe

def render(template_key: str, params: str) -> str:
    if template_key not in KNOWN_TEMPLATES:
        raise ValueError("unknown_template")
    key = f"{template_key}:{params}"
    with _lock:
        hit = _cache.get(key)
    if hit is not None:
        return hit
    value = expensive_render(template_key, params)
    with _lock:
        _cache[key] = value
    return value
```

Why this works: memory is now `MAX_ENTRIES × entry size`, not a function of traffic. TTL
bounds staleness as well as size. `lru_cache(maxsize=N)` works when no TTL is needed;
`maxsize=None` recreates the vulnerability.

"We only cache small strings" bounds entry size, not entry count. Unbounded count times any
positive size is unbounded. In Node, prefer an LRU with both `maxSize` and a
`sizeCalculation`; a bare `Map` has no eviction.

## L2 — Listener and Subscription Accumulation

`A06:2025` · `CWE-401`

Node's signal is `MaxListenersExceededWarning`. It appears at 11 listeners by default. Do
not raise the warning threshold before finding who registers per request.

```typescript
// Vulnerable: listener and captured request survive disconnect
app.get("/jobs/:id/stream", (req, res) => {
  jobBus.on("progress", (e) => {
    if (e.jobId === req.params.id) res.write(JSON.stringify(e));
  });
});
```

```typescript
// Fixed: named handler, one cleanup for normal and error exits
app.get("/jobs/:id/stream", (req, res) => {
  const onProgress = (e: ProgressEvent) => {
    if (e.jobId === req.params.id) res.write(JSON.stringify(e));
  };
  jobBus.on("progress", onProgress);
  const cleanup = () => jobBus.removeListener("progress", onProgress);
  res.on("close", cleanup);
  res.on("error", cleanup);
});
```

Why this works: removal receives the same function reference and runs when the socket closes.
An identical inline arrow passed to `removeListener` is a different object and removes nothing.

React is the same lifetime rule:

```typescript
// Vulnerable: re-subscribes after every render; fetch survives unmount
useEffect(() => {
  socket.subscribe(channel, setMessages);
  fetch(`/api/channels/${channel}`).then((r) => r.json()).then(setMeta);
});
```

```typescript
// Fixed: unsubscribe and abort are owned by the effect
useEffect(() => {
  const controller = new AbortController();
  const unsubscribe = socket.subscribe(channel, setMessages);
  fetch(`/api/channels/${channel}`, { signal: controller.signal })
    .then((r) => r.json()).then(setMeta)
    .catch((e) => { if (e.name !== "AbortError") setError(e); });
  return () => { unsubscribe(); controller.abort(); };
}, [channel, socket]);
```

An `isMounted` flag only suppresses the state update. It does not cancel the request or release
its buffers and captured closure. `AbortController` does.

## L3 — Connection and Handle Exhaustion

`A06:2025` · `A10:2025` · `CWE-772`

Pools belong to the process. A pool constructed per request is a socket leak.

```python
# Vulnerable: new pool per call, owner discarded
async def get_user(user_id: int):
    pool = await asyncpg.create_pool(DSN, min_size=5, max_size=20)
    return await pool.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
```

```python
# Fixed: create at startup, acquire per call, close at shutdown
pool = await asyncpg.create_pool(
    DSN, min_size=5, max_size=20, command_timeout=5, timeout=2
)

async def get_user(user_id: int):
    async with pool.acquire() as conn:
        return await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)

await pool.close()  # process shutdown
```

Why this works: the context manager returns the connection on exceptions as well as success.
The acquire timeout turns saturation into a fast failure instead of an indefinite wait.

Go's error path needs `defer` after the error check:

```go
// Vulnerable without Close: an early Scan error holds the connection
rows, err := db.QueryContext(ctx, query)
if err != nil { return nil, err }
defer rows.Close() // Fixed: every return releases; never defer before checking err
for rows.Next() {
    if err := rows.Scan(&name); err != nil { return nil, err }
}
return names, rows.Err()
```

Set `SetMaxOpenConns`, `SetMaxIdleConns`, and `SetConnMaxLifetime`. Go's default open limit is
unlimited. The same scope rule applies to files, sockets, cursors, locks, and C# `using`.

## L4 — Timer and Background Task Leaks

`A06:2025` · `CWE-772`, `CWE-400`

```typescript
// Vulnerable: interval holds client forever
function attach(client: Client) {
  setInterval(() => client.ping(), 30_000);
}

// Fixed: caller owns teardown
function attach(client: Client): () => void {
  const timer = setInterval(() => client.ping(), 30_000);
  timer.unref();
  return () => clearInterval(timer);
}
```

Python tasks need an owner. The event loop holds weak references, so a dropped task may be
collected before completion and its exception may go unseen.

```python
# Vulnerable: no owner, no await, no observed failure
asyncio.create_task(send_webhook(payload))

# Fixed: structured concurrency owns completion and cancellation (Python 3.11+)
async with asyncio.TaskGroup() as tg:
    tg.create_task(send_webhook(payload))
```

`asyncio.TaskGroup` was added in Python 3.11. On older versions, explicitly await `gather`.
For genuine fire-and-forget, hold a strong reference and remove it on completion:

```python
background.add(task)
task.add_done_callback(background.discard)  # without this, the set becomes L1
```

A Go goroutine blocked on a channel is the same shape:

```go
// Vulnerable: sender blocks forever if caller stops receiving
func fetch(url string, out chan<- Result) { out <- doFetch(url) }

// Fixed: cancellation is an exit path
func fetch(ctx context.Context, url string, out chan<- Result) {
    result := doFetch(ctx, url)
    select {
    case out <- result:
    case <-ctx.Done():
    }
}
```

Use `errgroup.WithContext` plus `SetLimit` for bounded fan-out. Structured concurrency is the
structural fix: a scope cannot finish while its children still run.

## L5 — Closure Capture and Accidental Retention

`A06:2025` · `CWE-401`

A garbage collector frees unreachable objects. A leak is a reachable object nobody wants.

```javascript
// Vulnerable: global listener retains detached row and its descendants
function attachRow(row) {
  const nodes = row.querySelectorAll("*");
  document.addEventListener("keydown", () => highlight(nodes));
  row.remove();
}

// Fixed: one abort releases the listener; teardown releases the row
function attachRow(row) {
  const controller = new AbortController();
  document.addEventListener("keydown", () => highlight(row), {
    signal: controller.signal,
  });
  return () => { controller.abort(); row.remove(); };
}
```

Chrome heap snapshots call the vulnerable result a detached DOM node. A growing detached count
across snapshots is the signal.

`WeakMap` is appropriate for metadata whose lifetime should follow an object key. It is not a
cache for string keys and not a substitute for finding the retainer.

```python
# Vulnerable: parent <-> child cycle and finalizer-controlled cleanup
child.parent = parent
parent.children.append(child)

# Fixed: weak parent edge; use explicit close/context management for resources
child._parent = weakref.ref(parent)
parent.children.append(child)
```

Why this works: the weak parent link no longer keeps the cycle alive. Prefer explicit `close()`
or a context manager to `__del__`, whose timing is nondeterministic.

## L6 — Request-Scoped State Stored Globally

`A01:2025` and `A06:2025` · `CWE-401`

This is a confidentiality bug first and a leak second.

```python
# Vulnerable: pooled worker can expose the previous request's user
current_user = {}

def middleware(request, next):
    current_user["value"] = request.user
    return next(request)
```

```python
# Fixed: context-local value restored on every exit
current_user: ContextVar[User | None] = ContextVar("user", default=None)

async def middleware(request, call_next):
    token = current_user.set(request.user)
    try:
        return await call_next(request)
    finally:
        current_user.reset(token)
```

Why this works: `reset(token)` prevents the next request from observing stale state, including
when the handler raises. A `ContextVar` set without reset, or a thread local never cleared
before returning to its pool, still leaks across work.

## L7 — Large Payloads Read Fully Into Memory

`A06:2025` · `API4:2023` · `CWE-770`, `CWE-789`

```python
# Vulnerable: client chooses one allocation and list() creates another
body = await request.body()
rows = list(csv.DictReader(io.StringIO(body.decode())))
```

```python
# Fixed: count bytes received, reject, then process bounded batches
MAX_BYTES = 10 * 1024 * 1024
total, buffer = 0, io.BytesIO()
async for chunk in request.stream():
    total += len(chunk)
    if total > MAX_BYTES:
        raise HTTPException(413, "payload_too_large")
    buffer.write(chunk)
for batch in batched(parse_rows(buffer), 1_000):
    save_batch(batch)
```

Why this works: the cap uses bytes received, not attacker-controlled `Content-Length`.
Enforce the same cap at the gateway. Stream database rows with a cursor or `yield_per`; never
call `.all()` on a query whose result grows with the table.

## L8 — Unbounded Queue or Buffer

`A06:2025` · `API4:2023` · `CWE-400`, `CWE-770`

```python
queue = asyncio.Queue()  # Vulnerable: maxsize=0 is unlimited
queue.put_nowait(event)
```

```python
# Fixed: bounded and explicit rejection at a public boundary
queue = asyncio.Queue(maxsize=10_000)
try:
    queue.put_nowait(event)
except asyncio.QueueFull:
    metrics.increment("ingest.rejected")
    raise HTTPException(503, "backpressure", headers={"Retry-After": "1"})
```

Why this works: memory is bounded by depth times event size, and saturation is visible. Reject
where a client can retry; block with `await queue.put()` inside a pipeline; drop only genuinely
disposable data and count every drop.

## N+1, Pagination, Cache Correctness, and Retries

`A06:2025` · `API4:2023` · ASVS V2, V13 · `A01:2025` where data crosses tenants

```python
# Vulnerable: one list query, then one customer query per row
orders = session.query(Order).limit(100).all()
for order in orders: print(order.customer.name)

# Fixed: eager load and retain a server-side result cap
orders = session.query(Order).options(selectinload(Order.customer)).limit(100).all()
```

Assert query count per request. Use keyset pagination instead of deep `OFFSET`, and cap page
size server-side.

```python
key = f"report:{report_id}"              # Vulnerable: shared across tenants
key = f"report:{tenant_id}:{report_id}"  # Fixed: identity participates in the key
```

For stampede control, let one bounded lock owner recompute, give the lock its own expiry, and
serve a fallback or reject other callers. A lock with no expiry can outlive a crashed owner.

```python
# Vulnerable: no timeout, 100 fixed-delay retries
for _ in range(100):
    try: return requests.get(url)
    except Exception: time.sleep(1)

# Fixed: per-call timeout inside a total budget, capped attempts, jitter
for attempt in range(3):
    remaining = deadline - time.monotonic()
    if remaining <= 0: raise TimeoutError("budget_exhausted")
    try: return requests.get(url, timeout=min(2, remaining))
    except requests.RequestException:
        time.sleep(min(0.1 * 2 ** attempt + random.random() * 0.1, remaining))
```

Retries amplify a failing dependency. Never retry a non-idempotent write without an
idempotency key.

## Measure Before Optimising

State the workload, duration, metric, baseline, and result. "Reduced allocations by 40 %"
without a workload is not evidence. Profile first — speculative optimisation often adds an
L1 cache to a cold path.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://docs.python.org/3/library/asyncio-task.html>
- <https://pkg.go.dev/database/sql#DB.SetMaxOpenConns>
