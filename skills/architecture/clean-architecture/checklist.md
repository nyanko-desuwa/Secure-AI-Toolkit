# Clean Architecture Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. A not-applicable answer
needs one sentence; silence is indistinguishable from an oversight.

## Dependency Direction

- [ ] Domain and application code import no web framework, ORM, serializer, or DI container
- [ ] Source dependencies point inward; infrastructure implements interfaces owned by inner layers
- [ ] Project references or import-linter rules enforce the direction, rather than folder names alone
- [ ] Repository interfaces use domain types, not ORM rows or framework query types
- [ ] No `IQueryable`, lazy relation, ORM session, or query builder crosses an inner-layer boundary
- [ ] Any framework exception is translated before it reaches the domain

## Actor and Authorization (`A01:2025` · ASVS V8)

- [ ] Every security-relevant use case takes an explicit, non-optional actor parameter
- [ ] Actor identity and tenant derive from a verified credential, never a request body or header
- [ ] The use case decides permission for the intent; controller guards are defence in depth
- [ ] Every read, write, and delete is scoped to the actor's tenant or ownership
- [ ] Background jobs, CLI commands, message handlers, and tests provide a named principal
- [ ] System actors are restricted, greppable, and included in the audit trail
- [ ] Authorization failure denies; dependency failure never grants access
- [ ] Missing and not-owned objects have an indistinguishable response where existence is sensitive

## Entities and Validation (`A05`, `A06` · ASVS V2)

- [ ] Edge schemas validate format, type, range, length, and reject unknown fields
- [ ] Domain constructors or factories enforce business invariants
- [ ] Invalid entities cannot be constructed through a public constructor or mutable setter
- [ ] Every alternate entry point uses the same entity factory
- [ ] Rehydration is a named, restricted path and does not become a general invariant bypass
- [ ] Domain operations prevent invalid transitions, not only invalid initial state

## Ports and Repositories

- [ ] Each port is defined in the layer that calls it
- [ ] Repository methods reveal intent and include tenant/ownership where needed
- [ ] Results are materialized inside the adapter; lazy loading does not cross the boundary
- [ ] Repository per aggregate has not created an unmeasured 1+N query path
- [ ] Query count is asserted in a test where N+1 is plausible
- [ ] List methods have a server-side maximum and stable pagination
- [ ] Read-only projections skip aggregate construction when invariants are not needed
- [ ] Database row-level isolation is considered where one omitted predicate has severe impact

## Input and Output DTOs (`API3:2023`)

- [ ] Input commands explicitly list writable fields and reject unknown keys (`CWE-915`)
- [ ] Output DTOs explicitly list readable fields; no entity or ORM model reaches the serializer
- [ ] No object spread, reflection convention, or automatic mapper silently copies new fields
- [ ] Field-level authorization happens while building the DTO, with the actor available
- [ ] Exact response keys are asserted in a test for sensitive resources
- [ ] DTOs exclude password hashes, reset tokens, internal flags, risk scores, and unrelated tenant IDs

## DI and Resource Lifetime (`A01`, `A06`)

- [ ] Use cases, repositories, ORM contexts, actor context, and tenant context are scoped per unit of work
- [ ] No singleton captures a scoped user, tenant, request, ORM context, cursor, or connection
- [ ] Singleton use cases have no instance-field lookup cache
- [ ] Long-lived caches include tenant in the key where values are tenant-specific
- [ ] Every cache has a maximum size and TTL or an explicit reason for no TTL
- [ ] Scope validation or the container's equivalent runs in CI
- [ ] A singleton worker creates and disposes one scope per job/message
- [ ] The container disposes what it creates; manually created resources have `using`, `with`, or `finally`
- [ ] No resource lifetime is longer than the unit of work that owns it
- [ ] Heap-level concerns are handed to `skills/architecture/performance/`, not hand-waved here

## Cancellation and Outbound Ports (`API4:2023`)

- [ ] Every I/O port method accepts the runtime's cancellation/deadline primitive
- [ ] Cancellation propagates from entry point through use case and port without becoming a field
- [ ] Each adapter sets a dependency-specific timeout linked to the caller's deadline
- [ ] Response and request sizes are bounded on bytes actually read or sent
- [ ] Retries have an attempt cap, total budget, jitter, and idempotency rules
- [ ] Cancellation and timeout failures do not leave a partial write or fail authorization open

## Cost and Fit

- [ ] Mapping allocations per response are acknowledged; hot list paths project directly to DTOs
- [ ] Query count per request is known for aggregate list paths
- [ ] ORM change tracking does not retain an unbounded result set until request end
- [ ] Every one-implementation interface has a reason: boundary enforcement, replacement, or compilation
- [ ] A thin controller plus scoped query was considered for CRUD with no domain rules
- [ ] The pattern is not used for a read-only report that can safely project directly to a DTO
- [ ] No claim of faster, safer, or lower-memory behaviour is made without a measurement or test

## Before Returning

- [ ] Relevant build or type-check completed and output is reported honestly
- [ ] Unit tests cover invariant construction and state transitions
- [ ] Integration tests cover controller bypass, job caller, and cross-tenant access
- [ ] Query-count and exact-response-shape tests run where applicable
- [ ] Temporary files removed, including `.gitkeep`
- [ ] Anything unverifiable at runtime is stated as a limitation, not marked pass
