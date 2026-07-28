# Clean Architecture Skill

## Purpose

Clean Architecture is useful here only when it makes an enforcement point unavoidable. The
dependency rule points source-code dependencies inward: entities and use cases do not import
frameworks, interface adapters translate, and infrastructure implements ports owned by inner
layers.

This skill focuses on the security and runtime consequences of that structure:

- authorization belongs in a use case that receives an explicit actor and intent;
- entities enforce invariants so every entry point gets the same rule;
- ports prevent infrastructure queries and tenant filters leaking into the domain;
- output DTOs prevent entities from exposing password hashes, internal flags, or other tenants'
  identifiers;
- DI lifetimes prevent request data and connections being retained by singletons;
- repositories and mappers have query, allocation, and retention costs.

## How It Works

The skill is Markdown. Nothing executes. Read `SKILL.md` first, then open the supporting file
that matches the decision. Use `best-practices.md` for design, `examples/README.md` for before and
after code, and `checklist.md` before returning an implementation.

```text
SKILL.md                         entry point and workflow
README.md                        purpose, layout, limitations
best-practices.md                security and cost-aware patterns
common-mistakes.md               failures and structural fixes
troubleshooting.md               conflicts and diagnosis
prompts.md                       prompts and anti-patterns
references/dependency-rule.md    primary dependency-rule source
references/di-lifetimes.md       named DI framework source
examples/README.md               eight before/after pairs
```

## File Layout

A practical project may use these packages:

```text
src/
  domain/          entities, value objects, ports; no web or ORM imports
  application/     use cases, actor, commands, output DTOs
  adapters/        controllers, presenters, repository implementations
  infrastructure/  ORM, HTTP clients, queues, configuration
```

The names are not the control. Enforce the direction with project references, package boundaries,
import-linter rules, or compilation in a framework-free domain test. A folder called `domain`
that imports Prisma is not a domain boundary.

## Configuration

There is no configuration for this skill. The examples use illustrative TypeScript, C#, and
Python. Adapt registration syntax to the container and version you actually run.

For .NET, register a `DbContext`, repository, and use case as scoped by default for HTTP work;
register only stateless, process-lifetime services as singleton. Enable scope validation in CI.
For another container, verify whether it rejects captive dependencies, bubbles request scope, or
silently promotes an object. This skill does not assume all containers behave alike.

## Example Usage

```text
Review src/application and src/infrastructure with skills/architecture/clean-architecture.
For every use case, show the actor parameter, authorization decision, repository port, and output
DTO. Count database queries for list paths. Report any dependency that points outward.
```

```text
Design a shipment use case with an HTTP controller and a CSV job caller. Put format validation
at the edge, invariants in the entity, tenant authorization in the use case, and the repository
interface in the inner layer. State mapping allocations and DI lifetimes.
```

```text
Check this registration for captive dependencies. Identify request-scoped data held by a
singleton, what the container will dispose, and how a worker should create a per-job scope.
```

## Limitations

- Markdown guidance is not a dependency scanner, query-plan profiler, or runtime leak detector.
  Pair it with compiler project-reference checks, SAST, integration tests, and heap/query
  measurement.
- It cannot prove a repository implementation applies a tenant predicate merely because its
  interface includes `tenantId`. Test cross-tenant reads and writes, and use database isolation
  where the consequence warrants it.
- It cannot infer actual container behaviour from a registration snippet. Scope validation,
  disposal, request scope bubbling, and factory ownership vary by framework and version. Verify
  against the pinned framework documentation.
- Output DTOs prevent accidental field exposure, not every privacy violation. A field that is
  intentionally copied can still be too sensitive for the actor; authorization decides that.
- The cost guidance is directional. Mapping and query counts must be measured with your payload
  sizes, database latency, connection pool, concurrency, and memory ceiling.
- This skill is not DDD, hexagonal architecture, CQRS, or service-level architecture. It links
  to adjacent skills rather than prescribing those patterns.

## Security Notes

The examples deliberately contain vulnerable code. Blocks labelled Vulnerable are teaching
material, not templates. They include cross-tenant queries, leaked fields, captive dependencies,
missing cancellation, and invalid entities.

Relevant mappings are `A01:2025` Broken Access Control, `A05:2025` Injection where input shape or
mass assignment is involved, `A06:2025` Insecure Design, `A10:2025` Mishandling of Exceptional
Conditions, and API Security Top 10 `API1:2023`, `API3:2023`, and `API4:2023`. ASVS references are
chapter-level only: V2, V8, V14, V15, and V16 as applicable. Do not infer a requirement ID from
these chapter citations.

## When It Is the Wrong Choice

A two-endpoint CRUD app with no domain rules gets four layers of indirection and zero benefit.
Use a thin controller plus a scoped, tenant-scoped query. A report can project directly into a
DTO. A short-lived script can have one visible enforcement point. Clean Architecture earns its
cost when there are multiple entry points or invariants that a database constraint cannot
express. See the teeth in [SKILL.md](SKILL.md#when-not-to-use-this).

## References

- [Dependency rule](references/dependency-rule.md)
- [DI lifetimes](references/di-lifetimes.md)
- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE](https://cwe.mitre.org/)
