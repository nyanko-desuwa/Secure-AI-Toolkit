# CQRS Skill

Separating commands from queries, and closing the hole the split opens.

## Purpose

Ask an AI for CQRS and you get a `Commands` folder, a `Queries` folder, a `MediatR`
registration, and a read model that nobody scoped. The pattern arrived; the authorization did
not.

This skill exists because a read model is a second path to the same data. On the command side
an aggregate loads state, checks the rule, and refuses. On the query side there is a `SELECT`
written for a dashboard, against a projection whose columns were chosen for rendering. If the
projection does not carry the tenant and the owner, that `SELECT` returns other people's rows
and looks entirely correct while doing it.

The second reason it exists: CQRS is the most over-applied pattern in this collection. The
skill says out loud when the answer is one model and one table.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, picks a level from the level
table (0 to 4), works the eight-step workflow, and pulls in the supporting file for the step it
is on. The `allowed-tools` frontmatter restricts it to reading, searching, and web lookup plus
`ls` and `cat`; it cannot run arbitrary commands.

```text
SKILL.md                        levels 0-4, flow diagram, workflow, when NOT to use
README.md                       this file
checklist.md                    pre-return verification, grouped by side
best-practices.md               patterns with code, each with a security and a cost note
common-mistakes.md              what goes wrong, plus the wrong fixes people reach for
troubleshooting.md              when the split does not fit or conflicts
prompts.md                      prompts that produce structure, plus an anti-pattern table
references/
  cqrs-sources.md               Fowler, Azure Architecture Center, outbox, dates verified
  owasp-cqrs-mapping.md         Top 10 2025, API Top 10 2023, ASVS 5.0, CWE per failure
examples/
  README.md                     eight before/after pairs
```

## Standards Covered

| Standard | What it covers here | Version | Verified |
|---|---|---|---|
| OWASP Top 10 | A01 Broken Access Control, A04 Cryptographic Failures, A06 Insecure Design, A08 Integrity Failures | 2025 | 2026-07-28, `owasp.org/Top10/2025/` |
| OWASP API Security Top 10 | API1 BOLA, API3 Object Property Level Authorization, API4 Resource Consumption | 2023 | 2026-07-28, `owasp.org/API-Security/` |
| OWASP ASVS | V2 Validation and Business Logic, V8 Authorization, V11 Cryptography, V14 Data Protection | 5.0.0 (released 2025-05-30) | 2026-07-28, ASVS project page |
| CWE | 213, 367, 401, 770, 837, 915, 1220 | current | 2026-07-28, `cwe.mitre.org` |

ASVS citations are chapter level only. No requirement IDs are quoted, because 5.0.0 renumbered
them and a stale ID is worse than no ID.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/architecture/cqrs/SKILL.md` is readable, or copy the `cqrs` directory into
`~/.claude/skills/`.

## Example Usage

Decide whether the split is warranted at all:

```text
Read skills/architecture/cqrs/SKILL.md. We have an admin screen that lists, creates, and
edits price rules. Roughly 40 writes a day, 2000 reads. Which level should we be at, and
what would level 3 cost us that level 1 does not?
```

Review a read model that already exists:

```text
Using skills/architecture/cqrs, review the projections in src/read-models/. For each one
tell me whether tenant and owner are part of the primary key, whether an unscoped query is
representable in the repository interface, and which columns should not be there.
```

Review a projector for resource lifetime:

```text
Review src/projectors/OrderTotalProjector.ts against the projector section of
skills/architecture/cqrs/best-practices.md. What grows per event, what bounds it, and what
happens on redelivery?
```

Plan a projection rebuild:

```text
We need to add owner_id to invoice_list_view, 60 million rows, in production. Walk the
replay-cost checklist and give me the operation as a runbook, not a deploy step.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not analysis. It cannot tell whether the projector is actually running,
  what the current projection lag is, or whether row-level security is enabled in the
  deployed database. Every claim about runtime state has to be verified against the running
  system.
- Cannot measure your read/write asymmetry. The skill insists you have a measurement before
  moving past level 1; it does not supply one.
- Languages are C# and TypeScript, with SQL for projections and one Java example for event
  schema evolution. Nothing here is Go, Rust, or PHP specific. The SQL is PostgreSQL flavour —
  `FOR UPDATE SKIP LOCKED`, `ON CONFLICT`, and row-level security syntax differ elsewhere.
- Resource-lifetime detail is deliberately thin. Bounds, leak shapes, backpressure, and heap
  diagnosis belong to `skills/architecture/performance/`; this skill names the projector
  hazard and links out.
- HTTP idempotency keys are not covered here. `skills/core/api-security/` owns header handling
  and response replay. This skill covers command-ID dedup inside the transaction, which is a
  different layer.
- Event sourcing coverage is intentionally partial. It covers replay semantics, PII erasure,
  and schema evolution — the parts that bite. It does not cover snapshot strategy in depth,
  event store product selection, or saga orchestration.
- Whether crypto-shredding satisfies a legal erasure obligation is a legal question. The skill
  describes the technique and says to get it reviewed. It is not legal advice.

## Security Notes

This skill contains deliberately broken code in `best-practices.md`, `common-mistakes.md`, and
`examples/`. Every such block is labelled `Vulnerable:` and paired with a fixed version. Do not
copy a labelled-vulnerable block into a project.

Two things in here are confidentiality bugs rather than design smells, and should be treated as
incidents if found in production:

- A projection without a tenant column, read by any query that forgets to filter. That is
  cross-tenant data disclosure, `A01:2025`, not a modelling preference.
- A denormalised view built with `SELECT *` across joined tables, serialized to a response.
  Password hashes and MFA secrets reach clients this way, `API3:2023`.

Authorization decisions must not read from an eventually consistent projection. This is stated
in the workflow, in best practices, and in the checklist, because it is the failure most likely
to be introduced by an assistant optimising a permission check.

Event stores holding personal data need an erasure path designed in before the first event is
written. Retrofitting one means rewriting the store.

All examples use placeholder values. No real credentials, hostnames, or personal data appear in
this skill.

## References

- Martin Fowler, CQRS — <https://martinfowler.com/bliki/CQRS.html>
- Azure Architecture Center, CQRS pattern — <https://learn.microsoft.com/en-us/azure/architecture/patterns/cqrs>
- microservices.io, Transactional Outbox — <https://microservices.io/patterns/data/transactional-outbox.html>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- GDPR Article 17, right to erasure — <https://gdpr-info.eu/art-17-gdpr/>
- CWE-1220 — <https://cwe.mitre.org/data/definitions/1220.html>
