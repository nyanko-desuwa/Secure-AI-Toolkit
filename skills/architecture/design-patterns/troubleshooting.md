# Design Patterns Troubleshooting

Use this when a pattern does not fit, conflicts with a control, or has already spread too far.

## Nobody can name the boundary

Ask for one sentence: "outside code may not do X directly". Then search for every direct import,
constructor, DI registration, raw client, plugin lookup, and script that can still do X.

If no prohibited action can be named, the pattern is ceremony. Remove it. If the action exists but
a bypass exists, close exports and registrations before adding another wrapper.

## Authorization exists in several layers

Do not choose a favorite layer from theory. Trace every entry point and identify the last point that
has authenticated actor, tenant, target resource, and operation together. Put the policy there and
make lower-level access require the scoped result.

Keep defense in depth where it is independent, such as row-level security. Delete duplicated checks
that disagree. Report any path that cannot be traced as unverified, not secure by assumption.

## The decorator is bypassed

1. Search direct construction of the wrapped class.
2. Search DI registrations by interface and concrete type.
3. Search tests, jobs, CLI tools, and reflection-based activation.
4. Move concrete construction to one composition module.
5. Export only the decorated interface.
6. Add a negative architecture test or import rule.

If the framework requires the concrete type to be public, enforce policy inside the implementation
as well and state the residual bypass risk. A wrapper alone is not A01 remediation.

## A Strategy registry became a plugin platform

Freeze registration after startup. Validate names against server-owned configuration. Give plugins
a narrow capability interface rather than the whole container. Bound plugin count, startup time,
and per-call execution. Fail closed when registration is ambiguous or duplicated.

If plugins are untrusted code, ordinary design patterns are not a sandbox. Process or OS isolation,
signed supply artifacts, and a threat model are needed; this skill does not provide them.

## The Factory needs every service

It has become a service locator. Split it by product family. Move application wiring to the
composition root. Make each factory's dependencies explicit and immutable.

A factory with one constructor call and no invariant can be deleted. Replace it with direct
construction until creation policy actually varies.

## The Adapter loses useful failure detail

Define a small error vocabulary: invalid request, rejected operation, unavailable dependency,
malformed dependency response. Preserve the original cause in protected logs and exception chaining,
but do not expose provider messages to clients.

Do not map an unknown failure to a successful default. That is A10 behavior and makes recovery
impossible to reason about.

## Listener count grows with requests

Instrument listener/subscription count and compare before and after repeated connect/disconnect
cycles. Search inline callbacks that cannot be removed by reference. Ensure cleanup runs on close,
error, cancellation, timeout, and normal completion.

If count stabilizes after warm-up, it may be a fixed process subscription. If it rises each cycle,
find the retaining publisher. One heap snapshot is not enough; use
`skills/architecture/performance/troubleshooting.md` for retained-reference diagnosis.

## The observer must guarantee delivery

An in-process Observer cannot guarantee delivery across crash and restart. If delivery is required,
write durable work in the same transaction as authoritative state and process it with idempotent
consumers. `skills/architecture/cqrs/` covers outbox and redelivery concerns.

Do not add retries to an in-memory callback without a total budget and queue bound. That converts a
transient failure into unbounded retained work.

## Singleton data appears under the wrong tenant

Treat it as a potential incident. Stop using the singleton for request state. Search static,
module-level, thread-local, and context-local values; identify where each is set and reset. Test two
requests on the same worker, including a failing first request and an unauthenticated second request.

Use explicit parameters where possible. If context-local storage is required, reset the token in
`finally`, and make missing context throw rather than return a stale default.

## Memoization consumes increasing memory

Measure key count, key cardinality source, entry size, hit rate, and eviction count. A cache that is
large but stable differs from one that grows across equal load intervals.

Set both capacity and lifetime where possible. If eviction changes correctness, it is not a cache;
it is an undocumented store. Move durable state to a store before adding eviction.

## Pool exhaustion persists after load drops

Check active leases, waiters, acquire latency, and release counts. Inspect every return, exception,
cancellation, and timeout path. A pool that stays exhausted after demand ends usually has a missing
release; a pool that recovers slowly may have long operations or a queue backlog.

Add scoped leases (`with`, `try/finally`, `using`) before raising capacity. Raising capacity can move
the outage to the database or dependency. CWE-772 is the missing release; CWE-770 is the unbounded
waiting or allocation.

## A bounded pool still uses unbounded memory

Pool size bounds objects, not waiting callers or work attached to them. Cap the queue before the
pool, reject or backpressure when full, and bound request payloads retained while waiting. Record
which behavior clients see.

## Pattern call stacks are impossible to debug

Draw the runtime path, not the class hierarchy. Include middleware, decorators, proxies, adapters,
callbacks, retries, and DI factories in order. Remove wrappers that neither transform data nor
enforce policy. Collapse pass-through interfaces.

Keep correlation in logs across the remaining boundary. Do not log secrets or entire external
responses. ASVS V16 requires useful error handling, not maximal data collection.

## Removing an over-applied pattern safely

Work one call path at a time:

1. Add characterization tests around observable behavior and policy denials.
2. Identify the abstraction with one caller and one implementation.
3. Inline it while preserving the public contract.
4. Delete its factory and mocks only after callers compile.
5. Re-run negative authorization and lifecycle tests.
6. Repeat; do not rewrite the subsystem in one change.

Removal is successful when the same boundary has fewer bypass paths and owned resources, not merely
fewer files.

## Two guides conflict

Prefer the option that makes authorization and cleanup structurally unavoidable. Performance does
not justify global request state, unbounded memoization, omitted tenant keys, or bypassable controls.
If a pool or cache is required by measurement, bound it and keep correctness independent of it.

## Runtime claim cannot be verified from source

State the missing observation and how to obtain it:

- DI graph: dump effective registrations at startup in a protected environment
- Listener leak: graph count across repeated lifecycle cycles
- Cache bound: read effective configuration and emit entries/bytes
- Pool leak: compare acquire/release and active lease counts
- Queue growth: emit depth, oldest-item age, rejection, and drop count
- Cleanup: inject failures and cancellation, then assert resource counts return to baseline

Do not infer production state from correct-looking source.
