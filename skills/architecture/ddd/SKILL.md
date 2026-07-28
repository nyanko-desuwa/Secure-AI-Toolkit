---
name: ddd
description: 'Domain-Driven Design where the boundary is a security boundary: bounded contexts as trust boundaries, aggregates as authorization units, value objects that cannot hold invalid state, and event contracts that do not grant capability. Triggers: "DDD", "bounded context", "aggregate root", "value object", "domain event", "anti-corruption layer", "ubiquitous language", "miền nghiệp vụ", "thiết kế theo miền".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# Domain-Driven Design

Two bounded contexts that write the same table share a blast radius. One team's migration
changes the meaning of a column, the other team's authorization filter still compiles, and
now a tenant reads rows that are not theirs. That is the failure this skill exists to
prevent, and no amount of folder naming prevents it.

DDD is worth its cost when the boundaries it draws are enforced. A context that is a
namespace, an aggregate that is a data holder, and an event bus with no payload contract
cost you indirection and buy you nothing.

## When to Use

- Splitting a system, or deciding whether two features belong in the same model
- A rule is enforced in one code path and skipped in another that writes the same data
- Two teams disagree about what `Customer`, `Account`, or `Order` means
- Integrating a legacy or third-party model into your own
- Reviewing generated "DDD" code: many folders, thin classes, logic in services
- An ID of the wrong kind reached a query and the query still ran

## Where DDD Creates or Removes a Boundary

| Construct | Boundary it creates | Hole when it is ceremony only |
|---|---|---|
| Bounded context | Trust boundary. Own schema, own DB role, published contract | Shared tables. One team's migration breaks the other's filter (CWE-653, CWE-1220) |
| Aggregate root | Consistency and authorization unit. Invariants enforced in one place | Setters on children, repository saves parts. Second write path skips the rule (A01) |
| Value object | Type boundary. An invalid value cannot exist | Primitive `string` IDs. `tenantId` and `userId` swap silently (CWE-1220) |
| Domain event | Message boundary. Explicit, narrow payload | Full entity in the payload. Internal fields leak to consumers and logs (A01, A09) |
| Repository | Aggregate boundary. Whole aggregates in, whole aggregates out | Returns a query object. Filtering, including the tenant filter, happens outside |
| Anti-corruption layer | Trust boundary with an external model. Translation and validation point | Direct use of the vendor DTO. External data becomes domain state unchecked (CWE-501) |
| Ubiquitous language | No boundary. It reduces misunderstanding, which is real but not a control | Harmless when absent from code; do not sell it as security |

An event is a message, not a capability. A consumer that acts on `InvoiceApproved` without
re-checking the approver's authority has moved the authorization decision to whoever can
publish to the bus (`A01:2025`, CWE-863).

## Workflow

### 1. Find the contexts by finding the language breaks

Where the same word means two things, you have two contexts. Draw the map before the code.
Mermaid context map template in [best-practices.md](best-practices.md#bounded-context-is-a-trust-boundary).

### 2. Make each context boundary enforceable, not documented

Per context, name three things: which tables it owns, which DB role it uses, and the
contract other contexts call. If two contexts share a write path to one table, the boundary
does not exist yet — say so rather than drawing it.

### 3. Draw aggregates from invariants, not from data shape

An aggregate is whatever must be consistent in one transaction. If a rule needs two
aggregates to be correct, the rule is eventually consistent and you must say what happens
in the window. See [best-practices.md](best-practices.md#aggregate-is-the-consistency-and-authorization-unit).

### 4. Replace primitives that carry meaning

Every ID, money amount, email, and tenant reference becomes a type whose constructor
rejects invalid input. This removes the class of bug where validation exists but a caller
forgot to invoke it.

### 5. Fix the event contract before adding a subscriber

Payload is explicit and minimal. Consumers re-authorize. Handler subscription has a
documented removal point.

### 6. Price it

For each aggregate: what is loaded to change one field, how many rows, how often. For each
handler: what it retains and who unsubscribes. Costs table below, detail in
[best-practices.md](best-practices.md#what-ddd-costs-at-runtime).

### 7. Verify

Run [checklist.md](checklist.md). Unchecked items become a design change or a written,
owned residual risk.

## What It Costs

| Decision | Runtime cost |
|---|---|
| Large aggregate | Whole object graph loaded to change one field. Read/write split is the answer — `skills/architecture/cqrs/` |
| Repository per aggregate | N+1 loading across a collection of roots; retained entities in a long-lived unit of work |
| In-process event dispatch | One slow handler stalls the publishing transaction. No bound, no backpressure |
| Long-lived handler subscription | Retains the scope it closed over. A per-request handler on a global bus is a leak — `skills/architecture/performance/` |
| Eventual consistency between aggregates | A real correctness cost. Something is briefly wrong and someone must define what a reader sees |
| Value objects on hot paths | Allocation per wrap. Use language value types where available; measure before assuming it matters |

## When NOT to Use This

DDD on a domain with no complexity produces vocabulary and folders. Skip it when:

- The domain is a form saved to a table. A validated request DTO and one query is the right
  answer, and it is easier to audit than four indirections.
- The rules are all "field is required" and "user owns row". Put the ownership filter in the
  query and stop.
- There is one team, one schema, and one meaning per word. You have no context boundary to
  find.
- The system is a reporting or ETL pipeline. There is no invariant to protect, only a
  transformation.
- The code is a prototype whose model you expect to throw away. Modelling cost is paid up
  front and refunded only if the model survives.

Partial adoption is legitimate and usually correct: value objects for IDs and money, plus
ownership in the query, gets most of the security benefit at a fraction of the cost. Take
that and leave aggregates, events, and repositories out until an invariant justifies them.

The tell that DDD was applied as ceremony: you cannot answer "where is authorization
enforced" in one sentence. If the answer names four files, the pattern made the system
harder to secure.

## Severity

Rank by how many places a fix must land and whether a boundary exists at all.

- **Critical** — two contexts write one table and one of them filters by tenant. Cross-tenant
  read is one migration away, or already live.
- **High** — an invariant enforced in one service with a second write path around it; a
  consumer that treats an event as authorization.
- **Medium** — primitive IDs at call sites where two ID types are adjacent; a repository
  returning a query object; an event carrying more than the consumer needs.
- **Low** — inconsistent language, missing context map, aggregate slightly larger than
  needed with no measured cost.

## Related Skills

- `skills/core/owasp/` — the Top 10 and ASVS mapping these findings cite
- `skills/advanced/secure-architecture/` — trust boundaries and threat modelling at system level
- `skills/architecture/cqrs/` — the read/write split that fixes large-aggregate loading
- `skills/architecture/performance/` — handler retention, unbounded dispatch, heap detail
- `skills/core/database-security/` — per-context DB roles, schema grants, N+1
- `skills/architecture/event-driven/` — event transport, delivery, ordering

## Supporting Files

- [README.md](README.md) — purpose, layout, configuration, limitations, security notes
- [checklist.md](checklist.md) — pre-return verification, grouped by construct
- [best-practices.md](best-practices.md) — patterns with real code, each with its cost
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix holds
- [troubleshooting.md](troubleshooting.md) — when DDD does not fit or conflicts
- [prompts.md](prompts.md) — prompts that produce structure, plus an anti-pattern table
- [references/](references/) — one file per source, with the date verified
- [examples/README.md](examples/README.md) — eight before/after pairs
