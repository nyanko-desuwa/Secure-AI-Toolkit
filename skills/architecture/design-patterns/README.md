# Design Patterns Skill

Boundary-first guidance for choosing and reviewing design patterns in security-sensitive systems.

## Purpose

Generated pattern code often increases coupling while appearing to remove it. An interface with one
implementation adds navigation but no substitution boundary. A decorator checks permission, while
the concrete implementation remains injectable. An observer retains every request it has ever seen.
A singleton stores the current tenant. An object pool has no acquire timeout or bounded wait queue.

This skill requires a concrete reason for each pattern: a real boundary it makes enforceable or an
existing coupling it removes. It then accounts for bypass paths, exceptional conditions, retained
references, queues, cache growth, and resource release.

## How It Works

The assistant reads `SKILL.md`, identifies the design pressure, maps every entry point, chooses the
smallest mechanism, and runs only the relevant checklist sections. Supporting files provide
runnable TypeScript and Python, vulnerable/fixed pairs, negative tests, and removal advice.

```text
SKILL.md                         trigger, decision table, workflow, when not to use
README.md                        this file
checklist.md                     grouped pre-return verification
best-practices.md                patterns, security implication, runtime cost
common-mistakes.md               failure, reason, fix, why the fix holds
troubleshooting.md               conflicts, diagnosis, and pattern removal
prompts.md                       review and implementation prompts, anti-pattern table
references/
  pattern-sources.md             primary pattern and language sources
  security-mapping.md            OWASP 2025, ASVS 5.0, verified CWE mapping
examples/
  README.md                      seven vulnerable/fixed runnable pairs
```

## Standards Covered

| Standard | Scope in this skill | Version | Verified |
|---|---|---|---|
| OWASP Top 10 | A01 Broken Access Control, A05 Injection, A06 Insecure Design, A10 Mishandling of Exceptional Conditions | 2025 | 2026-07-28 |
| OWASP ASVS | V8 Authorization, V15 Secure Coding and Architecture, V16 Security Logging and Error Handling | 5.0.0 | 2026-07-28 |
| CWE | 401, 602, 653, 770, 772, 1220 | current entries | 2026-07-28 |

ASVS citations are chapter-level only. No ASVS requirement IDs are claimed.

## Configuration

None. The skill is Markdown and adds no runtime dependencies.

Keep the repository available so `skills/architecture/design-patterns/SKILL.md` can be read, or
copy this directory into the assistant's skill location.

## Example Usage

Choose rather than assume a pattern:

```text
Read skills/architecture/design-patterns/SKILL.md. Two payment providers differ in request and
error shape. Identify the boundary, decide whether Adapter plus Strategy is warranted, and show
the smallest TypeScript design. Include the authorization and runtime cost.
```

Review bypass paths:

```text
Using skills/architecture/design-patterns, review our authorization decorator. Find every direct
constructor and DI registration for the decorated interface. Prove whether callers can resolve the
undecorated implementation. Cite A01 and CWE-653 only where the bypass is representable.
```

Review lifetime:

```text
Review publishers, listeners, singleton services, caches, object pools, and internal queues. For
each, list owner, bound, release point, and behavior on exception, cancellation, and saturation.
Classify verified missing release or missing bounds using CWE-401/770/772.
```

Remove ceremony:

```text
Find interfaces with one implementation and one caller. For each, state the concrete boundary or
coupling it removes. Where there is none, propose the smallest inlining change and list tests that
prove behavior is unchanged.
```

More targeted prompts are in [prompts.md](prompts.md).

## Limitations

- Source review cannot prove runtime DI registrations, plugin sets, queue depth, listener count,
  cache hit rate, or pool saturation in a deployed process. Mark those claims unverified until
  observed.
- Patterns do not make code secure. They can centralize controls, but only if all entry points are
  forced through the boundary.
- Example capacities are illustrative. Derive queue, cache, and pool sizes from measured entry
  cost, concurrency, latency budget, and process limits.
- TypeScript examples target a current Node runtime; Python examples use Python 3.11 features where
  noted. Framework lifecycle hooks differ.
- Distributed transactions, event delivery semantics, and advanced memory profiling are not
  duplicated here. Use `skills/architecture/cqrs/` and `skills/architecture/performance/`.
- This is not a catalogue of every Gang of Four pattern. Patterns without a demonstrated boundary
  or coupling-removal case are deliberately omitted from recommendations.
- CWE mappings describe the verified weakness mechanism. A pattern name alone never establishes a
  CWE, severity, exploitability, or compliance result.

## Security Notes

Code marked `Vulnerable:` is intentionally unsafe and is paired with a fixed version. Do not copy a
vulnerable block into a project.

Treat these as confidentiality or authorization findings, not style issues:

- A process-scoped singleton captures actor, tenant, request, response, or transaction state.
- A repository allows unscoped reads or accepts tenant identity directly from untrusted input.
- A decorated policy can be bypassed by resolving or constructing the concrete implementation.
- A client-supplied discriminator selects a privileged strategy without server-side policy.

Treat these as availability findings:

- Observer or listener registrations have no unsubscribe path.
- Memoization or cache keys have no maximum cardinality or TTL.
- Pool acquisition has no timeout, release is absent on an exception path, or the pool's wait queue
  grows without a maximum.
- Callback failures are swallowed while processing continues with partial state.

All examples use synthetic identifiers and local in-memory resources. They contain no credentials,
real hostnames, personal data, or attack tooling.

## References

- Refactoring.Guru, Design Patterns Catalog — <https://refactoring.guru/design-patterns/catalog>
- Python `functools` — <https://docs.python.org/3/library/functools.html>
- Python `queue` — <https://docs.python.org/3/library/queue.html>
- Node.js Events — <https://nodejs.org/api/events.html>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- CWE entries — <https://cwe.mitre.org/>
