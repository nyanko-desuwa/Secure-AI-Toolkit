# Resource Lifetime Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable"
needs a one-line reason — an unexplained skip reads the same as an oversight.

Only the sections the change touches need running. A CSS change needs none of this.

## Acquisition Inventory

- [ ] Every allocation that outlives the call has a named owner
- [ ] Every acquisition has a release point reachable from every exit path
- [ ] Nothing new is stored at module or class level unless it is process-lifetime by design
- [ ] Anything process-lifetime is created once at startup, not lazily inside a handler

## L1 — Caches

- [ ] Every cache has a maximum entry count or a maximum byte size
- [ ] Every cache has a TTL, or a documented reason it never goes stale
- [ ] The key space is bounded, or the key includes only server-chosen values
- [ ] Cache keys include tenant or user identity where the value is user-specific
- [ ] `lru_cache(maxsize=None)` and bare `Map`/`dict` caches are not used as caches
- [ ] Stampede on an expensive key is handled with a bounded lock, not a longer TTL

## L2 — Listeners and Subscriptions

- [ ] Every `addEventListener`, `.on()`, and `subscribe()` has a matching removal
- [ ] Removal happens on error and cancellation, not only on normal completion
- [ ] Listener functions are named or stored, so removal can match by reference
- [ ] React `useEffect` returns a cleanup function and has a dependency array
- [ ] `AbortController` is used for fetches and streams started in an effect
- [ ] `AbortError` is filtered out of error reporting
- [ ] No `MaxListenersExceededWarning` appears in test or dev logs

## L3 — Connections and Handles

- [ ] Connection pools are created once per process, never per request
- [ ] Pool maximum size is set explicitly, not left at the library default
- [ ] Pool acquire has a timeout, so saturation fails fast instead of hanging
- [ ] Files, sockets, cursors, and locks are released with `with`, `try/finally`, `defer`,
      or `using` — not by a call at the end of the happy path
- [ ] `defer close` is placed after the error check, not before it
- [ ] Go: `SetMaxOpenConns`, `SetMaxIdleConns`, and `SetConnMaxLifetime` are set
- [ ] Shutdown closes the pool and drains in-flight work

## L4 — Timers and Background Tasks

- [ ] Every `setInterval` and `setTimeout` handle is stored and cleared by its owner
- [ ] Long-lived timers call `unref()` where the process should still be able to exit
- [ ] No `create_task` result is dropped; a scope owns it, or a strong reference is held
      with `add_done_callback(set.discard)`
- [ ] Structured concurrency (`TaskGroup`, `errgroup`, `WaitGroup`) is used for fan-out
- [ ] Fan-out concurrency is bounded — `SetLimit`, a semaphore, or a worker count
- [ ] Every goroutine has a guaranteed exit: context cancellation or a closed channel
- [ ] Background task failures surface somewhere. Nothing is silently swallowed

## L5 — Retention

- [ ] No closure captures a large object graph it does not use
- [ ] Removed DOM nodes have no remaining listener or reference holding them
- [ ] Python parent/child links use `weakref` where a cycle would otherwise form
- [ ] Cleanup uses an explicit `close()` or context manager, not `__del__`
- [ ] `WeakMap`/`WeakRef` is used for key-lifetime metadata, not as a leak workaround

## L6 — Request-Scoped State

- [ ] No request or session data is written to a module-level or static variable
- [ ] `contextvars` values are set with a token and reset in `finally`
- [ ] Thread locals are cleared before the thread returns to the pool
- [ ] Reading request context outside a request raises rather than returning stale data
- [ ] Cross-request contamination is treated as a data leak, `A01:2025`, not a slow leak

## L7 — Payload and Result-Set Size

- [ ] Request bodies have a byte cap enforced on bytes received, not on `Content-Length`
- [ ] The same cap exists at the proxy or gateway, not only in the application
- [ ] Uploads and large responses stream; nothing calls `read()` on an unbounded source
- [ ] Result sets use a cursor, generator, or batch loop — no `.all()` on an unbounded query
- [ ] Decompression has an output size limit, so a small archive cannot expand without bound

## L8 — Queues and Backpressure

- [ ] Every queue, channel, and buffer has a maximum depth
- [ ] The full behaviour is chosen and written down: block, drop, or reject
- [ ] Rejection returns 503 with `Retry-After`; drops are counted
- [ ] Full-queue and drop events are metrics, not just log lines

## Bounds and Limits

- [ ] Pagination has a server-side maximum page size, and invalid input is rejected
- [ ] Deep pagination uses keyset, not large `OFFSET`
- [ ] Every outbound call has a connect and read timeout
- [ ] Retries have an attempt cap, a total time budget, and jitter
- [ ] No retry on a non-idempotent write without an idempotency key
- [ ] Concurrency into any dependency is capped
- [ ] Every limit's value has a stated basis: measured p99, memory budget, or dependency quota

## Measurement

- [ ] A profile or measurement exists for anything claimed as an optimisation
- [ ] The workload used for the measurement is described
- [ ] Memory claims come from at least two snapshots under steady load, not one
- [ ] Query count per request is asserted in a test where N+1 is plausible

## Container and Runtime Configuration

- [ ] The runtime's memory ceiling is set relative to the container limit, with headroom
- [ ] Go: `GOMEMLIMIT` set explicitly if the process must respect a cgroup limit
- [ ] JVM: heap sizing checked against the container limit, native overhead budgeted
- [ ] Node: `--max-old-space-size` set below the container limit
- [ ] A memory-limit breach is alerted on before it becomes an OOMKill

## Before Returning

- [ ] Build or compile step run
- [ ] Relevant tests run, with output reported honestly
- [ ] Any leak reported without a reproduction is labelled as unconfirmed
- [ ] Restart schedules and raised limits are described as mitigations, never as fixes
- [ ] Temporary heap dumps and profiles deleted — they contain live secrets
- [ ] Anything unverifiable stated plainly, not implied to be fine
