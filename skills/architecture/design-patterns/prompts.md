# Prompt Examples

Prompts that force a boundary, a cost, and a negative path instead of producing pattern ceremony.

## Decide whether a pattern is warranted

```text
Read skills/architecture/design-patterns/SKILL.md. A module has one implementation, one caller,
and no measured change pressure. Decide whether to add an interface or pattern. Compare a direct
function, an interface, and no change. State the boundary and runtime cost for each.
```

## Find all bypasses

```text
Using skills/architecture/design-patterns, find every constructor, DI registration, raw client,
script, and job that can reach InvoiceStore. The intended boundary is tenant-scoped reads. List
paths that bypass it, show the smallest closure, and cite A01/ASVS V8/CWE-653 only where verified.
```

## Review a Strategy registry

```text
Review src/strategies/. For every discriminator, state who controls it, which capabilities it can
select, how unknown values fail, and whether the registry can grow without bound. Do not accept a
client-side allowlist as authorization. Include A06 and CWE-602 where the mechanism fits.
```

## Review an Adapter

```text
Read the payment adapter. List external fields and exceptions that cross the boundary. Check input
validation, explicit output shape, parameterized queries, timeout, retry, and error translation.
Show a TypeScript or Python fixed version without returning provider internals.
```

## Review a Decorator boundary

```text
Review the authorization decorator and its DI setup. Prove whether the concrete implementation can
be constructed directly by controllers, tests, jobs, or reflection. Check duplicate wrapping and
whether missing context fails closed. Report A01, ASVS V8, or CWE-653 only from evidence.
```

## Review observers and lifecycle

```text
Review every subscribe/on/addEventListener in src/. For each, name the owner, unsubscribe function,
normal and error cleanup, captured values, and behavior on cancellation and disconnect. Identify
listener growth and classify verified missing release as CWE-401/772. Use performance troubleshooting
for a two-snapshot runtime diagnosis.
```

## Review singleton state

```text
Find module-level, static, singleton, thread-local, and context-local state written during a request.
For each, tell me whether a later request can observe it, whether tenant/actor data crosses users,
and whether reset occurs in finally. Treat cross-request data as A01 first.
```

## Review caches, pools, and queues

```text
For each cache, memoizer, object pool, and queue, report key space, maximum entries/bytes, TTL,
acquire timeout, lease release, queue maximum, and full behavior (block/drop/reject). Identify what
can be driven by input and give a bound justified by measured p99 or a stated budget.
```

## Remove ceremony

```text
Find interfaces, factories, facades, and decorators with one implementation and no policy or
translation. For each, write the characterization test, inline plan, and residual risk. Preserve
security denials and cleanup tests.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Implement all design patterns" | No pressure or boundary; produces ceremony |
| "Add clean architecture" | Folders do not enforce authorization or ownership |
| "Use a factory everywhere" | Hides dependencies and creates a service locator |
| "Make it extensible with plugins" | Omits trust model, allowlist, isolation, and resource bounds |
| "Use a singleton for current user" | Cross-request confidentiality failure |
| "Add an event bus" | Omits ordering, durability, unsubscribe, and backpressure |
| "Cache this result" | Omits key identity, capacity, TTL, invalidation, and correctness |
| "Pool these objects" | Omits reset, lease release, contention, and whether reuse is measured |
| "Put authorization in a decorator" | Misses direct concrete construction and alternate registrations |
| "Wrap every dependency in an interface" | Adds mocks and indirection without a real substitution boundary |
| "Make the repository generic" | Often creates unscoped `get`/`all` paths |
| "Catch adapter errors and return defaults" | Hides exceptional conditions and corrupts state |
