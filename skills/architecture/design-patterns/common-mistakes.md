# Design Patterns Common Mistakes

Each mistake states what goes wrong, why, the fix, and why the fix holds. Pattern names do not make
boundaries real; only unbypassable interfaces and owned lifetimes do.

## Interface with one implementation and one caller

The mistake: every class receives an interface, factory, and mock although there is no variation,
policy boundary, or external contract.

Why: abstractions are mistaken for decoupling. The caller still changes whenever the implementation
changes, but navigation and tests now cross three files.

Fix: inline the interface until a second implementation or enforceable boundary exists. Test the
observable result rather than mocking every collaborator.

Why it works: fewer public seams means fewer bypass paths. Reintroducing an interface later is cheap
when its required operations are known. Do not speculate about them now.

## Strategy chosen by untrusted input

The mistake: a request sends `strategy: "admin"`, `format: "raw"`, or a class name, and a registry
instantiates it.

Why: configuration and authorization are conflated.

Fix: validate the discriminator against a closed allowlist, then derive the allowed strategy from
authenticated server-side policy. Reject unknown values.

Why it works: the client can request behavior but cannot grant itself capability. This is A01/A06,
ASVS V8/V15, and CWE-602 when client-side selection was the enforcement.

## Decorator beside a public concrete implementation

The mistake: DI resolves `AuthorizedReportReader`, but jobs and tests can construct `SqlReportReader`
directly.

Why: the decorator looks like a control, while the language/module boundary still exposes a bypass.

Fix: keep the concrete implementation private to the composition module and export only the
decorated interface. Search all constructors and registrations before claiming closure.

Why it works: there is one supported entry point. A named compartment with public internals is
CWE-653; broader operations than callers require may also be CWE-1220.

## Generic repository erases authorization intent

The mistake: `Repository<T>.get(id)`, `all()`, and `query(spec)` can read without actor or tenant.

Why: generic CRUD is optimized for reuse rather than policy.

Fix: expose intent-named methods whose signatures require scope, such as
`invoiceReader.byId(tenant, id)`. Keep raw clients out of application modules.

Why it works: an unscoped call is unrepresentable instead of merely discouraged. The cost is more
methods and mapping; that cost buys A01/ASVS V8 enforcement.

## Adapter that catches everything and returns a default

The mistake:

```python
# Vulnerable: outage and malformed response become a valid zero balance.
def balance(adapter, account):
    try:
        return adapter.fetch(account)["balance"]
    except Exception:
        return 0
```

Why: adapters are treated as places to make external failures disappear.

Fix: validate the response, translate known provider failures to typed domain failures, preserve the
cause for protected logs, and let unknown failures surface.

Why it works: callers cannot continue with fabricated state. Swallowing exceptional conditions is
A10:2025 and conflicts with ASVS V16.

## Dynamic query hidden inside a pattern

The mistake: an Adapter or Repository concatenates a sort field, table, filter, or predicate because
the outer interface looks safe.

Why: reviewers stop at the abstraction boundary.

Fix: parameterize values and allowlist identifiers that cannot be parameters. Keep the allowlist in
server code.

Why it works: the source of the string no longer controls executable syntax. This is A05:2025 and
ASVS V15. A pattern moves the injection sink; it does not neutralize it.

## Singleton captures request state

The mistake: a process-scoped service stores `currentUser`, `tenantId`, request headers, transaction,
or response for later methods.

Why: DI labels the service singleton, and convenience state is added after registration.

Fix: pass request values explicitly, or use a request/context-local value that is reset in `finally`.
Keep singleton fields immutable or process-owned.

Why it works: a later request cannot observe the previous request's identity. Treat this as an A01
data exposure and CWE-401 retention problem, not a harmless race.

## Observer registered and never removed

The mistake:

```typescript
// Vulnerable: each request adds a closure that captures response and tenant.
bus.on("changed", (event) => response.write(JSON.stringify(event)));
```

Why: registration is visible; the matching lifetime is not.

Fix: return an unsubscribe function, call it on completion, error, cancellation, and disconnect,
and use the identical callback reference for removal.

Why it works: the publisher no longer retains the closure graph after its effective lifetime.
CWE-401/772. Raising a listener warning threshold only hides the signal.

## Observer used for invariants or transaction order

The mistake: `OrderPlaced` observers reserve inventory, take payment, and write audit state, with
success determined by whichever callback happened to run.

Why: Observer appears to decouple services while silently making ordering and failure semantics
implicit.

Fix: keep required transaction steps in an explicit application service or use a durable workflow
whose compensation and delivery semantics are designed. Notify observers only after authoritative
state commits.

Why it works: business success has one owner. Observer is appropriate for independent effects, not
an invisible transaction coordinator.

## Memoization with no bound

The mistake: `@cache`, `lru_cache(maxsize=None)`, a module `dict`, or a `Map` memoizes input-derived
keys forever.

Why: memoization is added as a local optimization without considering process lifetime or key
cardinality.

Fix: use a defensible maximum and TTL; restrict the key space; include tenant in keys for scoped
values; make correctness independent of cache presence.

Why it works: memory is bounded by chosen capacity rather than cumulative traffic. This is
CWE-401/770 and A06. Forced garbage collection cannot reclaim reachable entries.

## Pool with an unbounded wait queue

The mistake: the pool has ten objects, but any number of callers can wait forever; a timeout path
also forgets to return leases.

Why: only pool capacity is counted, not queued demand and release paths.

Fix: cap waiting work, set acquire and operation timeouts, release in `finally`/context manager,
reset before reuse, and reject saturation visibly.

Why it works: total retained work is bounded and each lease has a release point. Missing limits map
to CWE-770; missing release maps to CWE-772.

## Object pool for cheap objects

The mistake: short-lived DTOs, buffers, or parsers are pooled without measurement.

Why: pooling sounds like fewer allocations.

Fix: profile first. Remove the pool if construction is cheap or reset is error-prone.

Why it works: modern runtimes often allocate short-lived objects cheaply. A pool promotes objects
to longer lifetimes, adds locks and queues, and risks cross-request contamination.

## Service locator disguised as Factory

The mistake: `factory.get(name)` can return any database, logger, repository, or policy object.

Why: centralized construction grows into hidden global dependency lookup.

Fix: factories construct one product family and receive dependencies explicitly. Composition roots
wire graphs; domain code does not query a container.

Why it works: dependencies become visible in signatures, test setup reflects real collaborators,
and privileged services cannot be selected by arbitrary strings.

## Catching callback errors and continuing silently

The mistake: an event bus catches every listener exception and advances without a failure metric,
retry, or dead-letter policy.

Why: keeping the publisher alive is mistaken for successful processing.

Fix: define whether callbacks are best-effort or required. Observe failures, bound retries, and
surface partial completion. Never advance durable position after silently losing a required event.

Why it works: exceptional conditions cannot corrupt state invisibly. A10:2025 and ASVS V16 apply.
