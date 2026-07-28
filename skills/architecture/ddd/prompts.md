# DDD Prompts

Prompts that force structure, security boundaries, and runtime cost into the answer. A good
DDD prompt names a write path and an invariant. "Use DDD" does neither.

## Find the Bounded Contexts

```text
Read src/sales, src/billing, migrations, and database grants. Build a context map from
language breaks and table ownership. For each context name: tables it writes, DB role,
published contracts, data accepted from other contexts, and where that data is validated.
Flag any table written by two contexts as CWE-653/CWE-1220. Do not infer isolation from
folders alone.
```

Why it works: it asks for enforceable evidence — grants and writers — rather than boxes.

## Review One Aggregate

```text
Review the Order aggregate and every code path that persists orders. Name the invariant
that defines the boundary. Show whether the root is the only mutation path, whether child
collections escape, and whether repository/ORM code can save a partial aggregate. For each
finding, show the bypass path and a fix that makes the bypass impossible.
```

## Find Authorization Spread Across Services

```text
The rule is "only a manager with a limit at least as high as the invoice total may
approve". Find every Invoice write path: API, batch job, import, admin command, and raw
repository save. Report which path skips the rule. Move the invariant to the only object
that can see all its values and add a regression test for the bypass.
```

## Replace Security-Relevant Primitives

```text
Find functions where tenantId, userId, accountId, and invoiceId are all strings. Convert
them to nominal/branded types with validated construction at the HTTP/message boundary.
Show one test that the raw invalid value is rejected and one compile-time example where a
UserId cannot be passed as TenantId. Do not wrap display-only strings.
```

## Design a Domain Event Contract

```text
Design the InvoiceApproved domain event. Include only fields named by each consumer; never
spread the Invoice entity. For every consumer state what it re-authorizes and which local
state is authoritative. Define commit ordering, idempotency key, duplicate handling,
retention, and what happens when a handler is slow.
```

## Review Event Handler Lifetime

```text
Find every event-bus on/addListener/subscribe call. For each, name the subscription owner,
its lifetime, the returned disposer/unsubscribe handle, and where that handle is invoked on
success, error, cancellation, and host shutdown. Flag constructors that register handlers
without removal as CWE-401. Hand heap-level diagnosis to skills/architecture/performance/.
```

## Size an Aggregate

```text
For the ChangeOrderLine command, estimate rows/bytes loaded, rows written, lock/version
scope, and retained entities. Identify objects held only because of an ORM relationship.
Keep values needed by a real invariant; replace other aggregate references with IDs. If
reads need the large joined shape, propose a CQRS read model instead of weakening the write
invariant.
```

## Design an Anti-Corruption Layer

```text
Integrate the vendor customer JSON without importing vendor DTOs into the domain. Parse
unknown input strictly, reject unknown fields, map identifiers and enums, construct Email
and Money value objects, and derive TenantId from authenticated local context rather than
the payload. State translation cost and what happens when the vendor adds a field.
```

## Decide Whether DDD Is Worth It

```text
This feature stores a validated profile form and lets the owner update it. List the actual
invariants and language breaks. If there are none beyond field validation and ownership,
say DDD is not justified and implement a validated request plus a tenant-scoped query.
Do not create repositories, domain events, or aggregate folders without a rule that pays
for them.
```

## Resolve a Cross-Aggregate Rule

```text
The rule spans Account.creditLimit and the sum of open Orders. Show the race when two
commands run concurrently. Give three options: one aggregate, database-enforced invariant,
or eventual consistency with compensation. For each state transaction scope, contention,
staleness window, reader behaviour, and recovery when compensation fails. Recommend one
from the stated business requirement, not from pattern preference.
```

## Verify Before Returning Code

```text
Run skills/architecture/ddd/checklist.md against the change. Mark each item pass, fail, or
not applicable with a one-line reason. Do not mark the context isolated without checking
migrations and DB grants. Do not mark handler lifetime correct without finding the release
point. State any runtime behaviour source cannot verify.
```

## Anti-Patterns

| Prompt | What it produces | Better instruction |
|---|---|---|
| "Use DDD" | Folders and interfaces with no rule | Name the invariant and every writer |
| "Create aggregate roots for all entities" | Aggregate per table, no consistency boundary | Group only state that must commit together |
| "Make this enterprise-grade" | Events, repositories, and DI without consumers | Ask what boundary or cost each construct earns |
| "Add a generic repository" | `IQueryable` leaks and caller-owned tenant filters | Repository per root with scoped, materialised methods |
| "Publish the entity when it changes" | Full-entity event leaks internal fields | Name each consumer and the minimal payload it needs |
| "Make events reliable" | Unbounded retries or a vague bus abstraction | Require outbox, idempotency, bounds, retention, failure state |
| "Validate inputs in the service" | Eleven validators, the twelfth call skips one | Construct value objects at the trust boundary |
| "Split into bounded contexts" | Distributed transaction disguised as architecture | Name language break, table owner, contract, and consistency cost |
| "Optimize the aggregate" | Premature primitive use or broken invariant | Measure rows loaded, contention, and retained graph first |
| "Is this DDD correct?" | Terminology recital | Ask for bypass paths, transaction boundaries, and runtime cost |

## Reporting Shape

For each finding, require this shape:

```text
Boundary: Invoice aggregate
Failure: bulk import writes status directly, bypassing self-approval and limit checks
Standard: A01:2025, CWE-284, ASVS V8
Evidence: src/import/invoices.ts:74 -> repository.save(row)
Fix: private status; Invoice.approve(actor, limit) is the only transition
Why it removes the option: direct assignment no longer compiles
Cost: importer must map rows to aggregates; one load per invoice unless batched
Residual gap: raw SQL writer still exists in ops/reconcile.sql
```

This forces the answer to show an actual bypass, not praise or condemn the pattern by name.
