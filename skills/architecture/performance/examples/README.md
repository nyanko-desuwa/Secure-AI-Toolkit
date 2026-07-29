# Performance Examples

Vulnerable code next to its fix, one per leak shape. Each names the OWASP category, the CWE,
and why the fix closes the hole rather than looking safer.

The scenarios here are deliberately different from the ones in
[best-practices.md](../best-practices.md) - same eight shapes, different code, different
languages, so the pattern is visible apart from any one API.

## Contents

- [L1 - Rate limiter that leaks one entry per IP](#l1--rate-limiter-that-leaks-one-entry-per-ip) - A06, CWE-401
- [L2 - Observer attached and never disconnected](#l2--observer-attached-and-never-disconnected) - A06, CWE-401
- [L3 - HttpClient per request, sockets exhausted](#l3--httpclient-per-request-sockets-exhausted) - A06, CWE-772
- [L4 - Ticker goroutine with no exit](#l4--ticker-goroutine-with-no-exit) - A06, CWE-772
- [L5 - One field kept, the whole payload retained](#l5--one-field-kept-the-whole-payload-retained) - A06, CWE-401
- [L6 - ThreadLocal on a pooled servlet thread](#l6--threadlocal-on-a-pooled-servlet-thread) - A01, CWE-401
- [L7 - Archive extracted without an output bound](#l7--archive-extracted-without-an-output-bound) - A06, CWE-770
- [L8 - Ignoring the return value of `write()`](#l8--ignoring-the-return-value-of-write) - A06, CWE-400

---

## L1 - Rate limiter that leaks one entry per IP

`A06:2025` · `API4:2023` · `CWE-401` · ASVS V13

A limiter is supposed to be the thing that protects you. Written this way it is the fastest
way to fill memory, because every distinct source address earns a permanent entry.

```typescript
// Vulnerable: one Map entry per IP, forever
const hits = new Map<string, number[]>();

export function rateLimit(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip;
  const now = Date.now();
  const window = (hits.get(ip) ?? []).filter((t) => now - t < 60_000);
  window.push(now);
  hits.set(ip, window);                     // nothing ever deletes a key
  if (window.length > 100) return res.status(429).end();
  next();
}
```

The timestamp array is trimmed, so each entry stays small - and the entry count is unbounded.
Behind IPv6 an attacker has more addresses than you have bytes; a `/64` is 18 quintillion
keys. The limiter dies before the endpoint it protects.

```typescript
// Fixed: bounded key count with TTL eviction, and a bound on the value too
import { LRUCache } from "lru-cache";

const WINDOW_MS = 60_000;
const MAX_HITS = 100;

const hits = new LRUCache<string, number[]>({
  max: 100_000,          // ~100k tracked sources; sized from peak distinct IPs x 8
  ttl: WINDOW_MS,        // an idle source is forgotten when its window closes
  ttlAutopurge: true,    // evict on timer, not only on next access
});

export function rateLimit(req: Request, res: Response, next: NextFunction) {
  const now = Date.now();
  const window = (hits.get(req.ip) ?? []).filter((t) => now - t < WINDOW_MS);
  if (window.length >= MAX_HITS) {
    res.setHeader("Retry-After", "60");
    return res.status(429).end();
  }
  window.push(now);
  hits.set(req.ip, window.slice(-MAX_HITS));   // value cannot exceed MAX_HITS entries
  next();
}
```

Why this works: memory is now `max × MAX_HITS × 8 bytes` in the worst case - a number you can
write in a budget. Eviction under pressure drops the oldest tracked source, which is the
correct thing to lose: it had not sent a request recently.

The tempting wrong fix is a periodic sweep that deletes expired keys. It helps, but the growth
between sweeps is still unbounded, so a burst wins. A hard cap does not care about timing.

For a multi-instance deployment, move the counter to Redis with `EXPIRE`. That also fixes the
per-instance blind spot, where an attacker gets N times the allowance by spreading requests.

---

## L2 - Observer attached and never disconnected

`A06:2025` · `CWE-401` · ASVS V13

Not just `addEventListener`. `ResizeObserver`, `IntersectionObserver`, `MutationObserver`, and
`setInterval` all keep a strong reference to their target, which keeps the target and its
subtree alive after removal.

```typescript
// Vulnerable: an observer per card, none disconnected
class LazyImage {
  constructor(private el: HTMLElement) {
    const io = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) this.load();
    });
    io.observe(el);                          // observer outlives the element
  }
  destroy() {
    this.el.remove();                        // detached, still observed, still in memory
  }
}
```

Scroll an infinite list of 5 000 cards and you have 5 000 live observers, 5 000 detached
elements, and 5 000 closures holding `this`. Chrome DevTools shows this as a growing
`Detached HTMLImageElement` count between snapshots.

```typescript
// Fixed: the observer's lifetime is owned, and one call releases everything
class LazyImage {
  private io: IntersectionObserver;
  private controller = new AbortController();

  constructor(private el: HTMLElement) {
    this.io = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) {
        this.load();
        this.io.unobserve(el);               // one-shot: stop watching once loaded
      }
    });
    this.io.observe(el);
    el.addEventListener("error", this.onError, { signal: this.controller.signal });
  }

  destroy() {
    this.io.disconnect();
    this.controller.abort();                 // removes every listener on this signal
    this.el.remove();
  }
}
```

Why this works: `disconnect()` drops the observer's references to every target, and
`AbortController` removes listeners without needing to remember each function reference.
`destroy()` is now the single release point, so the audit question - who calls destroy - has
one answer instead of five.

A single shared observer for all cards is better still: one instance, `observe`/`unobserve`
per element, and the browser does the bookkeeping. One observer with 5 000 targets costs far
less than 5 000 observers with one target each.

---

## L3 - HttpClient per request, sockets exhausted

`A06:2025` · `CWE-772` · ASVS V13

C# earns its place here because the failure is counter-intuitive: `HttpClient` implements
`IDisposable`, so disposing it looks correct, and disposing it is exactly the bug.

```csharp
// Vulnerable: using-disposed per call. Correct-looking, exhausts sockets
public async Task<Invoice> GetInvoiceAsync(int id)
{
    using var client = new HttpClient();
    var res = await client.GetAsync($"https://billing.internal/invoices/{id}");
    return await res.Content.ReadFromJsonAsync<Invoice>();
}
```

Disposing the client closes the connection but leaves the socket in `TIME_WAIT` for minutes.
Under load the process runs out of ephemeral ports and every outbound call fails with
`SocketException`, including calls to healthy dependencies. Holding one static `HttpClient`
instead trades this for a subtler bug: it never picks up DNS changes, so a failover leaves it
talking to a dead address.

```csharp
// Fixed: pooled handler with a connection lifetime, injected per call site
builder.Services.AddHttpClient<BillingClient>(c =>
{
    c.BaseAddress = new Uri("https://billing.internal/");
    c.Timeout = TimeSpan.FromSeconds(5);            // no call holds a connection forever
})
.ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
{
    PooledConnectionLifetime = TimeSpan.FromMinutes(2),   // recycles, so DNS is re-resolved
    MaxConnectionsPerServer = 50,                        // bounded fan-out per dependency
});

public sealed class BillingClient(HttpClient http)
{
    public async Task<Invoice> GetInvoiceAsync(int id, CancellationToken ct) =>
        await http.GetFromJsonAsync<Invoice>($"invoices/{id}", ct);
}
```

Why this works: the handler is shared, so connections are reused instead of re-established, and
`PooledConnectionLifetime` closes them on a schedule so DNS changes are picked up without
disposing anything per request. `MaxConnectionsPerServer` bounds concurrency into the
dependency, which is the difference between degrading and taking it down with you.

The general lesson transfers: pooled transports are process-scoped. Python `requests.Session`,
Node's `http.Agent`, and Go's `http.Client` all behave the same way, and all three are commonly
constructed per call in generated code.

---

## L4 - Ticker goroutine with no exit

`A06:2025` · `CWE-772`, `CWE-400` · ASVS V13

```go
// Vulnerable: ticker never stopped, goroutine never exits
func StartCacheRefresh(c *Cache) {
    go func() {
        t := time.NewTicker(30 * time.Second)
        for range t.C {
            c.Refresh()
        }
    }()
}
```

Called once at startup this is merely untidy. Called per tenant, per connection, or on every
reconnect it is a leak: each call adds a goroutine, a runtime timer, and a strong reference to
the cache. The goroutine has no exit path at all - `for range t.C` on a ticker that is never
stopped blocks forever.

```go
// Fixed: caller-owned lifetime, guaranteed exit, ticker released
func StartCacheRefresh(ctx context.Context, c *Cache, wg *sync.WaitGroup) {
    wg.Add(1)
    go func() {
        defer wg.Done()
        t := time.NewTicker(30 * time.Second)
        defer t.Stop()                       // releases the runtime timer

        for {
            select {
            case <-ctx.Done():
                return                       // the exit path
            case <-t.C:
                ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
                if err := c.Refresh(ctx); err != nil {
                    log.Warn("cache_refresh_failed", "err", err)
                }
                cancel()
            }
        }
    }()
}
```

Why this works: `ctx.Done()` gives the goroutine a way out that the caller controls, `defer
t.Stop()` frees the timer, and the `WaitGroup` lets shutdown prove the goroutine finished
rather than assuming it. The per-tick timeout stops one slow refresh from stalling every
subsequent one.

Detect the vulnerable version without a profiler: `curl
localhost:6060/debug/pprof/goroutine?debug=1` and look for a count that rises with tenant
count and never falls. Assert it in a test with `runtime.NumGoroutine()` before and after,
which catches the regression at review time.

---

## L5 - One field kept, the whole payload retained

`A06:2025` · `CWE-401` · ASVS V13

```javascript
// Vulnerable: the session keeps a substring of a 40 MB response
async function loadProfile(session, userId) {
  const res = await fetch(`/api/users/${userId}/full-export`);
  const body = await res.text();                   // 40 MB string
  const parsed = JSON.parse(body);
  session.displayName = parsed.profile.displayName;
  session.audit = parsed;                          // whole graph retained
  session.rawSlice = body.slice(0, 64);            // and so is the 40 MB backing string
}
```

Two retentions. `session.audit` is the obvious one. The subtle one is `rawSlice`: in some
engines a sliced string keeps a pointer to its parent's backing buffer, so a 64-character
"summary" holds 40 MB alive. Sessions are long-lived, so this grows with logged-in users, not
with requests.

```javascript
// Fixed: extract what is needed, drop the rest, force a copy of the slice
async function loadProfile(session, userId) {
  const res = await fetch(`/api/users/${userId}/summary`);   // ask for less
  const parsed = await res.json();

  session.displayName = String(parsed.profile.displayName);
  session.auditRef = parsed.auditId;                          // an id, not the graph
  session.rawSlice = parsed.digest.substring(0, 64).split("").join("");  // copy, not a view
}
```

Why this works: nothing long-lived holds a reference into a large buffer. The narrower endpoint
is the real fix - the client never allocates 40 MB, so no amount of retention matters. Where
you cannot change the endpoint, copy the field you keep and let the parsed object go out of
scope.

The tempting wrong fix is `session.audit = new WeakRef(parsed)`. It makes the retention
optional rather than removing it: the value may vanish at any collection, so every read needs
a fallback path, and you now have both a leak-shaped design and a nondeterministic one. Weak
references are for caches whose loss is acceptable, not for data you intend to read.

---

## L6 - ThreadLocal on a pooled servlet thread

`A01:2025` and `A06:2025` · `CWE-401` · ASVS V8, V13

This is a data leak that looks like a memory leak. Java shows it most clearly because servlet
containers pool threads aggressively and reuse them across unrelated users.

```java
// Vulnerable: set per request, never removed. The thread outlives the request
public final class TenantContext {
    private static final ThreadLocal<Tenant> CURRENT = new ThreadLocal<>();

    public static void set(Tenant t) { CURRENT.set(t); }
    public static Tenant get() { return CURRENT.get(); }
}

public class TenantFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        TenantContext.set(resolveTenant(req));
        chain.doFilter(req, res);            // if this throws, nothing is cleared
    }
}
```

Request A sets tenant `acme` on thread 7. Request B arrives on thread 7 without a resolvable
tenant - an unauthenticated path, a health check, a request whose resolution threw - and
`TenantContext.get()` returns `acme`. Queries are now scoped to the wrong tenant. Rank this
critical: it serves one customer's data to another, and it is timing-dependent, so it will not
appear in tests.

The memory side is real too. The value is reachable from the pooled thread for as long as the
pool lives, and in a container that redeploys without restarting the JVM, a `ThreadLocal`
holding an application-classloader object keeps the entire old classloader alive.

```java
// Fixed: removed in finally, and absence is an error rather than a stale value
public class TenantFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        TenantContext.set(resolveTenant(req));
        try {
            chain.doFilter(req, res);
        } finally {
            TenantContext.clear();           // runs on the exception path too
        }
    }
}

public final class TenantContext {
    private static final ThreadLocal<Tenant> CURRENT = new ThreadLocal<>();

    public static void set(Tenant t) { CURRENT.set(Objects.requireNonNull(t)); }
    public static void clear() { CURRENT.remove(); }

    public static Tenant require() {
        Tenant t = CURRENT.get();
        if (t == null) throw new IllegalStateException("no tenant in scope");
        return t;
    }
}
```

Why this works: `remove()` in `finally` means no request can observe a previous request's
value, and `require()` turns the dangerous case - nothing set - into a loud failure instead of
a silent fallback to whatever was there. `CURRENT.set(null)` is not equivalent: it leaves an
entry in the thread's map, so the classloader retention stays.

The same bug and the same fix apply to Python's `threading.local()` on a thread-pool executor
and to `contextvars` set without a `reset(token)`.

---

## L7 - Archive extracted without an output bound

`A06:2025` · `API4:2023` · `CWE-770`, `CWE-789` · ASVS V5

An input size limit is not an output size limit. Compression is why.

```python
# Vulnerable: input capped at 1 MB, output unbounded
MAX_UPLOAD = 1 * 1024 * 1024

@app.post("/import-bundle")
def import_bundle(upload: UploadFile):
    data = upload.file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "payload_too_large")

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            content = zf.read(name)          # decompresses fully into memory
            handle(name, content)
```

A 1 MB zip of zeros expands to gigabytes. `zf.read()` allocates the decompressed size, so the
process dies on a request that passed the size check. The declared size in the zip header is
attacker-controlled, so checking `ZipInfo.file_size` before reading is not a bound either.

```python
# Fixed: bound the decompressed total, the per-entry size, and the entry count
MAX_UPLOAD = 1 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 50 * 1024 * 1024
MAX_ENTRIES = 500
CHUNK = 64 * 1024

@app.post("/import-bundle")
def import_bundle(upload: UploadFile):
    data = upload.file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "payload_too_large")

    written = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        if len(zf.namelist()) > MAX_ENTRIES:
            raise HTTPException(413, "too_many_entries")

        for name in zf.namelist():
            if name.startswith("/") or ".." in Path(name).parts:
                raise HTTPException(400, "unsafe_entry_name")

            with zf.open(name) as src:               # streaming, not zf.read()
                while chunk := src.read(CHUNK):
                    written += len(chunk)
                    if written > MAX_TOTAL_UNCOMPRESSED:
                        raise HTTPException(413, "expanded_payload_too_large")
                    handle_chunk(name, chunk)
```

Why this works: the count is of bytes actually decompressed, checked every 64 KiB, so the
process aborts partway through a bomb instead of allocating its full expansion. `zf.open`
streams; `zf.read` does not. The entry count bound stops the many-small-files variant, where
each file is tiny and the metadata is the payload.

Two more bounds worth adding, both out of scope for the memory question but in scope for the
endpoint: a wall-clock timeout, because decompression is CPU too, and a check on free disk if
anything is written to it. The path check is here because extraction is also a traversal sink -
see `owasp-security` for that half.

---

## L8 - Ignoring the return value of `write()`

`A06:2025` · `API4:2023` · `CWE-400` · ASVS V13

Node's streams have backpressure built in and it is opt-in by accident: `write()` returns
`false` when the buffer is full, and ignoring that boolean turns the buffer into an unbounded
queue.

```javascript
// Vulnerable: producer never pauses, so the buffer absorbs the difference
async function exportRows(res, query) {
  const cursor = db.queryStream(query);
  for await (const row of cursor) {
    res.write(JSON.stringify(row) + "\n");     // return value discarded
  }
  res.end();
}
```

A client on a slow connection, or one that stops reading entirely, consumes rows from the
database faster than the socket drains. The difference accumulates in the response stream's
internal buffer. Ten such clients against a 10 million row table exhausts memory - and it costs
the attacker nothing, because reading slowly is free.

```javascript
// Fixed: pipeline propagates backpressure and cleans up on any failure
import { pipeline } from "node:stream/promises";
import { Readable, Transform } from "node:stream";

async function exportRows(res, query) {
  const toNdjson = new Transform({
    objectMode: true,
    transform(row, _enc, cb) { cb(null, JSON.stringify(row) + "\n"); },
  });

  try {
    await pipeline(Readable.from(db.queryStream(query)), toNdjson, res);
  } catch (err) {
    if (err.code !== "ERR_STREAM_PREMATURE_CLOSE") throw err;   // client hung up
  }
}
```

Why this works: `pipeline` stops reading from the source when the destination's buffer is full
and resumes when it drains, so memory is bounded by `highWaterMark` rather than by the speed
difference. It also destroys every stream in the chain when any one fails, which closes the
database cursor - the `for await` version leaks it whenever the client disconnects mid-export.

The manual equivalent, if you cannot use `pipeline`, is to check the return value and wait:

```javascript
if (!res.write(chunk)) {
  await once(res, "drain");
}
```

That is what `pipeline` does for you, minus the cleanup on error. The general shape applies
outside Node: a producer must be able to observe that the consumer is behind. If it cannot,
the buffer between them is an unbounded queue no matter what the API is called.

---

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cwe.mitre.org/data/definitions/400.html>
- <https://cwe.mitre.org/data/definitions/401.html>
- <https://cwe.mitre.org/data/definitions/770.html>
- <https://cwe.mitre.org/data/definitions/772.html>
- <https://cwe.mitre.org/data/definitions/789.html>
