# Resource Lifetime Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable"
needs a one-line reason - an unexplained skip reads the same as an oversight.

Only the sections the change touches need running. A CSS change needs none of this.

## Acquisition Inventory

- [ ] [recommended] Every allocation that outlives the call has a named owner
- [ ] [recommended] Every acquisition has a release point reachable from every exit path
- [ ] [recommended] Nothing new is stored at module or class level unless it is process-lifetime by design
- [ ] [recommended] Anything process-lifetime is created once at startup, not lazily inside a handler

## L1 - Caches

- [ ] [critical] Every cache has a maximum entry count or a maximum byte size
- [ ] [recommended] Every cache has a TTL, or a documented reason it never goes stale
- [ ] [recommended] The key space is bounded, or the key includes only server-chosen values
- [ ] [critical] Cache keys include tenant or user identity where the value is user-specific
- [ ] [recommended] `lru_cache(maxsize=None)` and bare `Map`/`dict` caches are not used as caches
- [ ] [recommended] Stampede on an expensive key is handled with a bounded lock, not a longer TTL

## L2 - Listeners and Subscriptions

- [ ] [critical] Every `addEventListener`, `.on()`, and `subscribe()` has a matching removal
- [ ] [recommended] Removal happens on error and cancellation, not only on normal completion
- [ ] [recommended] Listener functions are named or stored, so removal can match by reference
- [ ] [recommended] React `useEffect` returns a cleanup function and has a dependency array
- [ ] [recommended] `AbortController` is used for fetches and streams started in an effect
- [ ] [recommended] `AbortError` is filtered out of error reporting
- [ ] [recommended] No `MaxListenersExceededWarning` appears in test or dev logs

## L3 - Connections and Handles

- [ ] [recommended] Connection pools are created once per process, never per request
- [ ] [recommended] Pool maximum size is set explicitly, not left at the library default
- [ ] [recommended] Pool acquire has a timeout, so saturation fails fast instead of hanging
- [ ] [critical] Files, sockets, cursors, and locks are released with `with`, `try/finally`, `defer`,
      or `using` - not by a call at the end of the happy path
- [ ] [recommended] `defer close` is placed after the error check, not before it
- [ ] [recommended] Go: `SetMaxOpenConns`, `SetMaxIdleConns`, and `SetConnMaxLifetime` are set
- [ ] [recommended] Shutdown closes the pool and drains in-flight work

## L4 - Timers and Background Tasks

- [ ] [critical] Every `setInterval` and `setTimeout` handle is stored and cleared by its owner
- [ ] [recommended] Long-lived timers call `unref()` where the process should still be able to exit
- [ ] [critical] No `create_task` result is dropped; a scope owns it, or a strong reference is held
      with `add_done_callback(set.discard)`
- [ ] [recommended] Structured concurrency (`TaskGroup`, `errgroup`, `WaitGroup`) is used for fan-out
- [ ] [recommended] Fan-out concurrency is bounded - `SetLimit`, a semaphore, or a worker count
- [ ] [critical] Every goroutine has a guaranteed exit: context cancellation or a closed channel
- [ ] [recommended] Background task failures surface somewhere. Nothing is silently swallowed

## L5 - Retention

- [ ] [recommended] No closure captures a large object graph it does not use
- [ ] [recommended] Removed DOM nodes have no remaining listener or reference holding them
- [ ] [recommended] Python parent/child links use `weakref` where a cycle would otherwise form
- [ ] [recommended] Cleanup uses an explicit `close()` or context manager, not `__del__`
- [ ] [recommended] `WeakMap`/`WeakRef` is used for key-lifetime metadata, not as a leak workaround

## L6 - Request-Scoped State

- [ ] [critical] No request or session data is written to a module-level or static variable
- [ ] [critical] `contextvars` values are set with a token and reset in `finally`
- [ ] [critical] Thread locals are cleared before the thread returns to the pool
- [ ] [recommended] Reading request context outside a request raises rather than returning stale data
- [ ] [critical] Cross-request contamination is treated as a data leak, `A01:2025`, not a slow leak

## L7 - Payload and Result-Set Size

- [ ] [critical] Request bodies have a byte cap enforced on bytes received, not on `Content-Length`
- [ ] [recommended] The same cap exists at the proxy or gateway, not only in the application
- [ ] [recommended] Uploads and large responses stream; nothing calls `read()` on an unbounded source
- [ ] [recommended] Result sets use a cursor, generator, or batch loop - no `.all()` on an unbounded query
- [ ] [critical] Decompression has an output size limit, so a small archive cannot expand without bound

## L8 - Queues and Backpressure

- [ ] [critical] Every queue, channel, and buffer has a maximum depth
- [ ] [recommended] The full behaviour is chosen and written down: block, drop, or reject
- [ ] [recommended] Rejection returns 503 with `Retry-After`; drops are counted
- [ ] [recommended] Full-queue and drop events are metrics, not just log lines

## Bounds and Limits

- [ ] [recommended] Pagination has a server-side maximum page size, and invalid input is rejected
- [ ] [recommended] Deep pagination uses keyset, not large `OFFSET`
- [ ] [recommended] Every outbound call has a connect and read timeout
- [ ] [recommended] Retries have an attempt cap, a total time budget, and jitter
- [ ] [critical] No retry on a non-idempotent write without an idempotency key
- [ ] [recommended] Concurrency into any dependency is capped
- [ ] [recommended] Every limit's value has a stated basis: measured p99, memory budget, or dependency quota

## Measurement

- [ ] [recommended] A profile or measurement exists for anything claimed as an optimisation
- [ ] [recommended] The workload used for the measurement is described
- [ ] [recommended] Memory claims come from at least two snapshots under steady load, not one
- [ ] [recommended] Query count per request is asserted in a test where N+1 is plausible

## Container and Runtime Configuration

- [ ] [recommended] The runtime's memory ceiling is set relative to the container limit, with headroom
- [ ] [recommended] Go: `GOMEMLIMIT` set explicitly if the process must respect a cgroup limit
- [ ] [recommended] JVM: heap sizing checked against the container limit, native overhead budgeted
- [ ] [recommended] Node: `--max-old-space-size` set below the container limit
- [ ] [recommended] A memory-limit breach is alerted on before it becomes an OOMKill

## Before Returning

- [ ] [critical] Build or compile step run
- [ ] [critical] Relevant tests run, with output reported honestly
- [ ] [recommended] Any leak reported without a reproduction is labelled as unconfirmed
- [ ] [recommended] Restart schedules and raised limits are described as mitigations, never as fixes
- [ ] [recommended] Temporary heap dumps and profiles deleted - they contain live secrets
- [ ] [critical] Anything unverifiable stated plainly, not implied to be fine
