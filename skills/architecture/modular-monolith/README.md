# Modular Monolith

## Purpose

The controller calls another module's ORM because "it is in the same process". The module filter
is now optional, a migration can change its meaning, and the security boundary exists only in a
diagram. This skill replaces that convention with enforceable contracts, owned data, and tests.

A modular monolith has one process and deployment, but each module owns its domain rules and
persistence. Calls cross a typed application contract, not a table, ORM model, or mutable service.
Every recommendation below states the security boundary it creates and its runtime cost.

## How It Works

A module has a private domain, application use cases, adapters, persistence, and a narrow exported
contract. Other modules may depend on the contract package, never on private implementation.

```text
modules/
  sales/
    domain/ application/ adapters/ infrastructure/
    public/commands.ts public/queries.ts public/events.ts
    migrations/  (writes sales schema only)
  billing/
    domain/ application/ adapters/ infrastructure/
    public/commands.ts public/queries.ts public/events.ts
    migrations/  (writes billing schema only)
composition/     dependency wiring; no business rules
```

A contract carries an explicit `Actor`, tenant identity, validated command/query data, deadline,
and cancellation. The owning module performs authorization, applies its tenant predicate, maps to
an allowlisted result, and returns materialized data. It does not return `IQueryable`, a cursor, or
an ORM entity.

## Configuration

There is no universal framework configuration. Enforce boundaries with language project references,
package visibility, import-linter rules, database schemas and roles, migration ownership checks, and
CI contract tests. Register request/unit-of-work state per request, message, or job scope. Register
only stateless, bounded, process-lifetime components as singletons. Verify the actual container
because lifetime promotion differs by framework.

At the database layer, give each module a role with write grants only to its schema. If a shared
database cannot yet support this, mark the shared table as a residual risk and route non-owner
writes through the owner's contract while migrating.

## Example Usage

```text
Review modules/sales and modules/billing. For every import, table, query, command, and event,
show the owner and direction. Prove that actor tenantId reaches the owner's query, that no module
reads another module's table, and that state plus outbox rows commit atomically. Add contract tests
for cross-tenant reads, unauthorized commands, duplicate events, and schema drift. Report query,
allocation, queue, and retained-reference cost.
```

```text
Design a modular-monolith payment approval flow. Keep authorization in Billing, use a local
transaction and outbox, make the event minimal and idempotent, and state what happens if Sales is
slow, unavailable, or called twice. Do not use a global request-scoped singleton or a transaction
held across a module call.
```

## Limitations

Source structure cannot prove database grants, effective runtime limits, or that an adapter applies
the predicate in production. Verify grants, generated SQL, deployment configuration, and heap/queue
metrics. Contract types do not authenticate callers; the composition root must construct actors from
verified credentials. An outbox provides at-least-once delivery, not exactly-once effects. Consumers
must deduplicate and re-authorize.

One process also means a module can still exhaust the shared heap, CPU, connection pool, or event
loop. A private folder is not a process isolation boundary. Treat resource limits and failure
containment as explicit design decisions.

## Security Notes

This skill maps module bypasses and actor omissions to OWASP A01:2025 Broken Access Control and
A06:2025 Insecure Design. Unvalidated commands or flexible query fragments map to A05:2025 Injection.
Stale or leaked actor state, wrong cache keys, and internal fields in contracts map to A01. Rollback
or event ordering failures map to A10:2025 Mishandling of Exceptional Conditions. Outbox and
contract integrity can also affect A08:2025 Software or Data Integrity Failures.

Relevant ASVS chapters are V8 Authorization, V15 Secure Coding and Architecture, and V16 Security
Logging and Error Handling. Use V2 Validation and Business Logic and V4 API and Web Service when
commands or public adapters are involved. This skill specifically verifies CWE-602 (client-side
enforcement), CWE-653 (improper compartmentalisation), CWE-770 (allocation without limits),
CWE-772 (missing release), and CWE-1220 (insufficient granularity). CWE-602 applies when a client
or caller is trusted to enforce a module rule; the server-side owner must enforce it again.

## References

- [OWASP Top 10 2025](references/owasp-top10-2025.md)
- [OWASP ASVS 5.0](references/asvs-5.0.md)
- [CWE boundary and resource mappings](references/cwe-boundaries.md)
- `skills/architecture/clean-architecture/` for dependency direction and DI lifetimes.
- `skills/architecture/ddd/` for aggregates and bounded contexts.
- `skills/architecture/performance/` for heap, handle, queue, and cache diagnosis.
