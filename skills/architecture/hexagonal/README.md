# Hexagonal Architecture Skill

## Purpose

A port is a contract. An adapter is the only place where untrusted input becomes a domain type
and where a domain type becomes an outside-world message. This skill exists to keep those two
jobs in the adapter and keep the authorization decision behind the port, because the usual
failure is the reverse.

The failure this skill is written against: `POST /documents/:id/publish` verifies ownership in
the HTTP handler. Later a queue consumer and a cron job call the same use case. Neither checks
anything, because the check was drawn around one adapter instead of around the port.
`A01:2025`, `CWE-602`, `CWE-653`.

What the skill covers:

- driving ports that take the actor as a required parameter, so no adapter can call in anonymously;
- inbound adapters as the validation point, so a new adapter is not a new unvalidated entry point;
- driven ports that state what the core will accept, so a third-party response is refused before
  it becomes a domain object;
- outbound adapters as the SSRF choke point (`A06:2025`, `API7:2023`, `CWE-918`);
- error translation at the adapter, so a domain exception does not reach a client verbatim
  (`A10:2025`, `CWE-209`);
- adapter resource lifetime - clients, subscriptions, cursors, and queues (`CWE-772`, `CWE-401`,
  `CWE-400`, `CWE-770`);
- the cost of every interface, mapping step, and hidden query the pattern adds;
- when the pattern is the wrong choice, which is most of the time.

## How It Works

The skill is Markdown. Nothing executes. Read `SKILL.md` first - it holds the driving/driven
table, the workflow, the cost table, and the "when NOT to use this" section. Then open the file
that matches the decision in front of you.

```text
SKILL.md                             entry point, port directions, workflow, when not to use
README.md                            purpose, layout, limitations, security notes
best-practices.md                    patterns in Go, TypeScript, and Java, each with its cost
common-mistakes.md                   what goes wrong, why, the fix, why the fix holds
troubleshooting.md                   when the pattern does not fit or conflicts
checklist.md                         pre-return verification
prompts.md                           prompts that produce ports, plus an anti-pattern table
references/ports-and-adapters.md     Cockburn's original pattern description
references/owasp-top10-2025.md       the categories cited here
references/asvs-5.0.md               chapter-level ASVS mapping
references/api-top10-2023.md         API risks that land on adapters
references/cwe-adapter-weaknesses.md verified CWE titles used across the skill
examples/README.md                   eight before/after pairs
```

## File Layout

A layout that survives review. The names are not the control; the import direction is.

```text
src/
  core/
    domain/        entities, value objects, domain errors
    ports/         driving port interfaces + driven port interfaces, both owned here
    app/           use cases implementing driving ports, authorization policy
  adapters/
    inbound/       http/, queue/, cli/, cron/ - credential to Actor, payload to command
    outbound/      postgres/, egress-http/, secrets/, mail/
  composition/     the only place that knows both sides; wires and owns lifetimes
```

Rules that make it real: `core/` imports nothing from `adapters/`; `adapters/` may import `core/`;
`composition/` imports both and is the only package allowed to construct an adapter. Enforce it
with project references, Go internal packages, an import-linter contract, or ArchUnit - not with
a folder name. A `core/` package that imports `net/http` is not a core.

## Configuration

There is no configuration for this skill. Code is Go, TypeScript, and Java. Adapt client,
container, and broker syntax to the versions you actually run; connection-pool defaults, idle
timeouts, and DI scope behaviour differ per library and version, and this skill does not assume
they match the snippets.

## Example Usage

```text
Review src/core and src/adapters with skills/architecture/hexagonal. For every driving port,
list each adapter that calls it and show where the Actor comes from. Flag any port method that
does not take an actor, and any core signature that names a transport, ORM, or broker type.
```

```text
Design a RefundOrder use case in Go, driven by an HTTP handler and a queue consumer, and driving
a Postgres repository plus a payment provider. Put credential verification and payload parsing
in the adapters, the authorization decision in the use case, and state the client lifetime and
query count.
```

```text
Audit adapter resource lifetime. For every outbound adapter, show where the client is created,
whether it is created per call, whether it is bounded, and who closes it on shutdown. For every
inbound adapter, show subscribe/unsubscribe pairing and any queue between adapter and core.
```

```text
This service has one HTTP entry point, one table, and no third-party calls. Compare hexagonal
against the framework's own idioms. Count files, interfaces with one implementation, and
enforcement points. Recommend the simpler option unless a concrete second adapter exists.
```

## Limitations

- Markdown is not a static analyser. Pair it with import-direction enforcement in the build,
  SAST, contract tests against real adapters, and heap or query measurement.
- A port signature that names a tenant does not prove the adapter applies the predicate. Test a
  cross-tenant read against the real adapter, not the fake.
- Fake adapters can drift from real ones. A green suite against a fake proves the core's logic,
  not the adapter's behaviour. Run one contract suite against both.
- DI container behaviour - captive-dependency detection, disposal ownership, scope bubbling -
  varies by container and version. Verify against your container's documentation before relying
  on it to catch a singleton holding request state.
- SSRF defence by resolve-then-connect leaves a DNS rebinding window unless the checked address
  is pinned into the connection or an egress proxy fronts the call. The skill says which
  mitigations exist; it cannot confirm which one your HTTP client actually performs.
- Cost guidance is directional. Allocation counts, query counts, and socket counts depend on
  payload size, concurrency, and pool configuration. Measure.
- This skill is not DDD, CQRS, or clean architecture. It links to the sibling skills instead of
  restating them.

## Security Notes

Blocks labelled Vulnerable are teaching material. They contain deliberately unsafe code:
missing authorization, header-derived tenants, unbounded reads, per-call HTTP clients,
unsubscribed handlers, and raw exception rendering. Do not copy them.

Mappings used: `A01:2025` Broken Access Control, `A02:2025` Security Misconfiguration,
`A04:2025` Cryptographic Failures, `A05:2025` Injection, `A06:2025` Insecure Design,
`A10:2025` Mishandling of Exceptional Conditions. API risks: `API1:2023`, `API3:2023`,
`API4:2023`, `API7:2023`, `API10:2023`. ASVS 5.0 is cited at chapter level only - V2, V4, V8,
V13, V14, V15, V16 - and no requirement ID is inferred from a chapter citation.

CWE identifiers used in this skill were checked against `cwe.mitre.org` on 2026-07-28; the
titles are listed in [references/cwe-adapter-weaknesses.md](references/cwe-adapter-weaknesses.md).
No CVE, version number, or requirement ID is asserted anywhere in the skill.

## When It Is the Wrong Choice

One entry point, one database, no third-party calls: you get an interface with one
implementation, a mock nobody needs, and two extra files between a request and a query. Use the
framework's idioms and put the check in the service call. A CRUD admin panel has no domain to
protect. A single-queue worker gains a hop. A prototype freezes decisions it has not made. The
teeth are in [SKILL.md](SKILL.md#when-not-to-use-this).

One port with one adapter is still justified when the port exists to hold a security check or to
isolate an untestable dependency. Write that reason in a comment, or the next contributor will
inline it.

## References

- [Ports and adapters, the original description](references/ports-and-adapters.md)
- [OWASP Top 10 2025](references/owasp-top10-2025.md)
- [OWASP ASVS 5.0](references/asvs-5.0.md)
- [OWASP API Security Top 10 2023](references/api-top10-2023.md)
- [CWE entries used here](references/cwe-adapter-weaknesses.md)
- Related: `skills/core/api-security/`, `skills/core/database-security/`,
  `skills/architecture/clean-architecture/`, `skills/architecture/performance/`,
  `skills/architecture/scalability/`
