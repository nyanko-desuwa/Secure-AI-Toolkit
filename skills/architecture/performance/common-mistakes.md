# Common Mistakes

Failures seen repeatedly in generated and hand-written code. Each entry says what goes wrong,
why, and what closes it. Leak prevention comes first; misleading remediations come last.

## A `dict` called a cache

```python
_cache = {}

def lookup(key: str):
    if key not in _cache:
        _cache[key] = expensive(key)
    return _cache[key]
```

There is no eviction. If `key` comes from a request, the caller chooses how much memory the
process uses. This is L1: `A06:2025`, `CWE-401`, `CWE-770`.

Fix: `TTLCache(maxsize=N, ttl=S)` or `lru_cache(maxsize=N)`. `maxsize=None` is still
unlimited. On a method, `lru_cache` also pins `self`; cache the module-level function or use a
per-instance cache. See [best-practices.md](best-practices.md#l1--unbounded-cache).

## An inline listener that cannot be removed

```javascript
emitter.on("data", (d) => handle(d));
emitter.removeListener("data", (d) => handle(d));   // removes nothing
```

Removal matches by reference. Two identical arrows are different objects, so L2 remains
attached while the code looks cleaned up (`A06:2025`, `CWE-401`).

Fix: store the function, then pass the same reference to both calls. In React, every effect
that subscribes must return the unsubscribe function and have a dependency array.

## Pool created inside the function that uses it

```python
async def get_user(uid):
    pool = await asyncpg.create_pool(DSN)
    return await pool.fetchrow("SELECT ...")
```

"Uses a pool" reads as correct, but every call creates connections and drops their owner.
The database reaches `max_connections` and unrelated clients fail: L3, `A06:2025`,
`CWE-772`.

Fix: create one bounded pool at process startup, close it at shutdown, and acquire per call
with a context manager and an acquire timeout.

## Close on the happy path only

```python
f = open(path)
data = parse(f.read())    # raises on malformed input
f.close()                 # never reached
```

Failures skip release exactly when the process is already under stress. The same bug is
`rows.Close()` after a loop or `lock.release()` after work (`A10:2025`, `CWE-772`).

Fix: `with`, `try/finally`, `defer`, or `using`. In Go, check `err` before deferring a close;
deferring a method on a nil handle panics.

## A task or goroutine with no owner

```python
asyncio.create_task(send_webhook(payload))
```

The loop holds only a weak reference. The task may disappear before finishing, and its
exception is not retrieved. A global set without completion cleanup merely changes L4 into
L1 (`A06:2025`, `CWE-772`).

Fix: `asyncio.TaskGroup` on Python 3.11+, or hold the task and call
`task.add_done_callback(tasks.discard)`. In Go, every goroutine needs a cancellation path;
a send to a channel nobody reads blocks forever.

## Request context in a global

```python
_current_tenant = None    # set in middleware, never reset
```

A pooled worker serves the next request with the previous tenant. This is a cross-tenant
data leak, `A01:2025`, as well as L6 (`CWE-401`).

Fix: `ContextVar.set()` with `reset(token)` in `finally`. Clear thread locals before the
thread returns to its pool. Missing context must raise, not return stale data.

## Trusting `Content-Length`

```python
if int(request.headers["content-length"]) > MAX:
    raise HTTPException(413)
```

The client can understate the header, and chunked requests omit it. The allocation remains
unbounded: L7, `API4:2023`, `CWE-770`, `CWE-789`.

Fix: count bytes as they arrive and abort when the running total exceeds the cap. Enforce the
same cap at the gateway. Stream result sets instead of calling `.all()` without a limit.

## A queue with no full policy

`asyncio.Queue()` defaults to unlimited. A slow consumer turns it into L8 (`A06:2025`,
`API4:2023`, `CWE-400`).

Fix: set `maxsize`, then choose what full means: block, drop, or reject. Count drops and
rejections. Silently growing is not a policy.

## A cache key without the tenant

```python
key = f"report:{report_id}"
```

The first tenant to warm the entry serves every tenant. This is `A01:2025`, not a minor cache
bug. Fix: include tenant or user identity in the key and test isolation.

---

## The Wrong Fixes

### `gc.collect()` on a timer

A leak is reachable memory. The collector already reclaims unreachable objects, so forced
collection leaves the retainer in place and adds latency spikes. `global.gc()` and
`System.gc()` do the same. Collection is useful inside a diagnostic before measuring, not as
a scheduled remediation.

Fix: compare snapshots and find the growing retainer.
[troubleshooting.md](troubleshooting.md) gives the method.

### Raising the memory limit

Doubling `--max-old-space-size` or the container limit doubles time to OOM; it does not
change the slope. It can buy diagnosis time. Record it as mitigation, not resolution.

### A restart schedule

Restarting on memory pressure can keep a service available while diagnosis runs. It also
drops in-flight work and hides the next leak. Pair it with evidence capture and a tracked
root-cause investigation. Never close the finding as fixed.

### `WeakMap` everywhere

Weak references help metadata follow an object's lifetime. They do not help when another
retainer still holds the key, and they make required data nondeterministic. Use them only
when losing the value is acceptable and the key's lifetime is the intended lifetime.

### "A garbage-collected language cannot leak"

GC reclaims unreachable objects. A leak is a reachable object nobody wants. Managed
runtimes change a dangling pointer into unbounded growth; they do not remove L1-L8.

### One snapshot, one conclusion

One snapshot cannot distinguish a leak from a warm cache. Baseline, apply steady load,
snapshot, load again, snapshot again. Compare retained sets and find what keeps growing, not
what is merely large.

### Optimising the line you assumed was hot

Speculative optimisation often adds an L1 cache to a cold path. Profile first, state the
workload and metric, then change the measured bottleneck.
