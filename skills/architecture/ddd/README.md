# DDD Skill

Domain-Driven Design read as a set of boundaries, each of which is either an authorization
boundary or a hole.

## Purpose

Generated "DDD" code is usually vocabulary. Folders named `domain`, `application`, and
`infrastructure`; entities that are public setters; a service that validates before saving;
an event bus with no payload contract. The structure looks right and the security-relevant
question — where is authorization enforced — now has four possible answers.

This skill gives an assistant a fixed set of questions per construct:

- Bounded context: which tables does it own, which DB role, what contract do others call?
- Aggregate: what invariant does this boundary protect, and can any code path write past it?
- Value object: can this type hold a value the domain rejects?
- Domain event: what is in the payload, and does the consumer re-authorize?
- Repository: does it return whole aggregates, or a query the caller finishes?
- And for every one of them: what does it load, what does it retain, who releases it?

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, works the seven-step
workflow (find contexts, make boundaries enforceable, draw aggregates from invariants,
replace primitives, fix the event contract, price it, verify), and pulls in the supporting
file it needs.

```text
SKILL.md                        workflow, boundary/hole table, costs, when NOT to use
README.md                       this file
checklist.md                    pre-return verification, grouped by construct
best-practices.md               patterns with real code, each with its cost
common-mistakes.md              what goes wrong and why the fix holds
troubleshooting.md              when DDD does not fit, and what to do instead
prompts.md                      prompts that produce structure, plus an anti-pattern table
references/
  ddd-sources.md                Evans, Vernon, Fowler — what each is authoritative for
  security-standards.md         Top 10 2025, ASVS 5.0, CWE mapping per construct
examples/
  README.md                     six before/after pairs, real code
```

## Standards Covered

| Standard | What it covers here | Version | Verified |
|---|---|---|---|
| OWASP Top 10 | A01 Broken Access Control, A06 Insecure Design, A08 Integrity, A09 Logging | 2025 | 2026-07-28, `owasp.org/Top10/2025/` |
| OWASP ASVS | V2 Validation and Business Logic, V8 Authorization, V14 Data Protection, V15 Secure Coding and Architecture | 5.0.0 (released 2025-05-30) | 2026-07-28, ASVS project page |
| CWE | 284, 362, 401, 501, 653, 662, 863, 1220 | current | 2026-07-28, `cwe.mitre.org` |

ASVS citations are chapter level only. Requirement IDs changed in the 5.0 restructure; for
requirement-by-requirement verification work from the official ASVS repository.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/architecture/ddd/SKILL.md` is readable, or copy the `ddd` directory into
`~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read, search, and web
lookup plus `ls`/`cat`.

## Example Usage

Review a model for boundary integrity:

```text
Read src/billing and src/support with skills/architecture/ddd. For each bounded context
list the tables it writes and the DB role it uses. Report any table written by both.
```

Check whether an aggregate actually holds its invariant:

```text
Find every code path that persists an Invoice. For each one, say whether the
"total equals sum of lines" rule is enforced, and where. If any path writes the rows
directly, that is the finding.
```

Price an aggregate before accepting it:

```text
This Order aggregate loads customer, all lines, and inventory levels. Tell me what a
single status update costs in rows loaded and rows written, and whether a read/write
split would be cheaper.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not analysis. It cannot prove that no code path writes past an
  aggregate. It tells you to enumerate the write paths; finding all of them needs grep,
  a schema grant review, and in some cases a database audit log.
- Cannot confirm runtime state. Whether the DB role is actually restricted, whether the
  event dispatcher holds strong references, whether the unit of work is scoped per request
  in the deployed container — none of that is visible in source. Where a claim depends on
  runtime behaviour this skill says so, and you should too.
- Aggregate sizing has no rule. "Small" is relative to contention and row count. The skill
  tells you to measure loaded rows per operation and observe optimistic-concurrency
  conflict rates; it does not tell you the right number of entities.
- No transport or delivery guarantees. Outbox, ordering, idempotency, and retry belong to
  `skills/architecture/event-driven/`. This skill covers only the payload contract, commit
  ordering, and handler lifetime.
- No heap-level detail. Retention shapes are named and linked; the diagnosis method lives
  in `skills/architecture/performance/`.
- Languages are TypeScript, Python, and C# — C# where DI and unit-of-work lifetime are the
  point. Java and Kotlin appear where a language feature (records, sealed types) teaches
  something the others cannot. Nothing here is Go, Rust, or PHP specific.
- Says nothing about which DDD book's terminology to prefer where the sources differ. Where
  they differ, `references/ddd-sources.md` says which one is being followed.

## Security Notes

This skill contains deliberately broken code in `best-practices.md`, `common-mistakes.md`,
and `examples/`. Every such block is labelled `Vulnerable:` or `Wrong:` and paired with a
fixed version. Do not copy a labelled block into a project.

Two findings in this skill are confidentiality bugs, not design untidiness. A shared table
across two contexts where one filters by tenant is a cross-tenant read waiting for a
migration (`A01:2025`). A domain event carrying a full entity puts internal fields into
consumer code and into log pipelines (`A01:2025`, `A09:2025`). Treat both as data leaks
first and architecture second.

The examples use placeholder values only — `tenant-a`, `user@example.com`, `https://vendor.example.com`.
No real credentials, hostnames, keys, or personal data appear in this skill.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- Fowler, Bounded Context — <https://martinfowler.com/bliki/BoundedContext.html>
- Fowler, DDD Aggregate — <https://martinfowler.com/bliki/DDD_Aggregate.html>
- Vernon, Effective Aggregate Design — <https://domainlanguage.com/ddd/>
- CWE-653 — <https://cwe.mitre.org/data/definitions/653.html>
- CWE-1220 — <https://cwe.mitre.org/data/definitions/1220.html>
- CWE-863 — <https://cwe.mitre.org/data/definitions/863.html>
