# Prompt Examples

Prompts that produce enforcement points rather than folders. Good prompts name actors, entry
points, invariants, response fields, resource lifetime, and the cost to report.

## Design One Use Case

```text
Design an ApproveInvoice use case in C#. It is called by an HTTP controller and a nightly job.
The use case must take an explicit Actor, enforce invoice:approve and no self-approval, query by
tenant through an inner-layer repository port, return an explicit DTO, and propagate a
CancellationToken. Show DI lifetimes and query count. Do not generate unrelated files.
```

Why it works: the actor and alternate caller force authorization into the use case, while the
query count stops repository ceremony from hiding an N+1.

## Review Dependency Direction

```text
Read src/domain, src/application, and src/infrastructure. Draw the actual import graph, not the
folder names. Report every inward layer importing Express, ASP.NET, Prisma, EF Core, a serializer,
or the DI container. For each finding state the security consequence and the smallest dependency
inversion that removes the import.
```

Ask for the actual graph. Otherwise the answer repeats the intended architecture.

## Find Bypassable Authorization

```text
For each mutation use case, list every caller: controller, job, CLI, message handler, and test.
Show whether the use case signature requires an Actor and where actor plus intent are authorized.
Flag checks that exist only in a controller as A01:2025 / CWE-602. Do not accept authentication as
authorization.
```

## Check DTO Boundaries

```text
Trace every response from use case to serializer. Flag ORM models, domain entities, object spreads,
and reflection mappers. For each response, list the exact fields that leave and identify password
hashes, reset tokens, internal flags, risk fields, and unrelated tenant IDs. Fix with explicit
output DTOs and add an exact-key test. Map to API3:2023 and CWE-213.
```

## Place Validation Correctly

```text
Review create and update flows reached by HTTP and imports. Put format/type/unknown-key validation
at each edge and business invariants in constructors or factories. Demonstrate that no public
constructor can create an invalid aggregate. Name the rehydration bypass and who can call it.
```

## Review Repository Ports

```text
Review repository interfaces. Flag interfaces defined beside adapters, ORM return types,
IQueryable/query builders, lazy relations, methods without tenant scope, and missing cancellation.
Replace them with inner-layer, intention-revealing methods returning materialized domain objects.
Count queries for every list path before and after.
```

## Diagnose N+1

```text
For the order list endpoint, write the exact query equation: list query + per-row customer queries
+ per-row invoice queries. Assume a page of 100 and show the total. Compare batching, eager load,
and a direct DTO projection. Preserve tenant scoping in every option and add a query-count test.
```

## Review DI Lifetimes

```text
List every singleton and recursively list what it captures. Flag current actor, tenant, request,
DbContext/session, connection, cursor, repository, or use case dependencies with shorter
lifetimes. Show the stale-authorization path, retained object graph, correct registration, scope
validation configuration, and per-job scope for workers.
```

## Review Outbound Ports

```text
Trace cancellation from the entry point through use case and outbound port to the HTTP/database
adapter. Flag a missing token, missing adapter timeout, unbounded response read, unlimited retry,
or non-idempotent retry. Fix the port signature first, then the adapter. Map resource exhaustion
to A06:2025 / API4:2023 / CWE-770.
```

## Decide Whether to Use the Pattern

```text
This service has two CRUD endpoints, no business invariants, one HTTP entry point, and one table.
Compare a thin controller plus a scoped tenant query against entities + use cases + ports + DTOs.
State files to navigate, mapping allocations, query count, enforcement points, and the trigger that
would justify migrating later. Prefer the simpler design unless a concrete rule earns the layers.
```

## Verify Before Returning

```text
Run skills/architecture/clean-architecture/checklist.md against this change. Mark each applicable
item pass or fail with file:line evidence. For not applicable, give one sentence. Report unverified
runtime behaviour, query counts, container scope validation, and tests honestly.
```

## Anti-Pattern Table

| Prompt | Problem | Better constraint |
|---|---|---|
| "Make this clean architecture" | Produces folders and one interface per class | Name actor, alternate callers, invariant, DTO, cost |
| "Add repositories" | Returns generic CRUD or `IQueryable` | Ask for aggregate intent, tenant scope, query count |
| "Use dependency injection" | Says nothing about lifetime | Name singleton/scoped/transient and disposal owner |
| "Secure the controller" | Creates a bypass for every non-controller caller | Require actor in the use-case signature |
| "Add validation" | Leaves the layer ambiguous | Format at edge; invariant in constructor/factory |
| "Hide sensitive fields" | Encourages a deny list | Require explicit output DTO and exact-key test |
| "Optimize mapping" | Deletes security boundary without a profile | Profile, then direct projection to the same DTO |
| "Fix N+1 with includes" | Can produce row explosion or unbounded graphs | Show 1+N count and compare three bounded options |
| "Make the service singleton for performance" | Captures request state and a context | Inventory dependencies and prove process lifetime |
| "Add timeout in HTTP adapter" | Cancellation still cannot reach it | Add token to the port and thread it from the edge |
| "Abstract the framework" | Adds wrappers without a security boundary | Identify the forbidden import and the inner owner |
| "Apply all SOLID principles" | Ceremony without an enforcement point | Ask what becomes impossible after the change |

## Prompt Review Rule

Reject a generated design that cannot answer all five:

1. Who is the actor?
2. Where is actor plus intent authorized?
3. Can an invalid entity be constructed?
4. What exact fields leave the process?
5. What is acquired per request, who owns it, and when is it released?

Then ask for query count and mapping allocations. If the answer is four folders and no numbers,
the prompt produced a diagram, not an architecture.
