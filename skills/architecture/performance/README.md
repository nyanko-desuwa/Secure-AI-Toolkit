# Performance Skill

Resource lifetime for AI-assisted code review. Memory leaks first, limits second,
throughput last.

## Purpose

Generated code allocates confidently and releases carelessly. It writes a module-level
`cache = {}` with no eviction, adds an event listener in a request handler, creates a
connection pool inside the function that uses it, and reads the whole response body into a
string. Each of those passes tests, passes review, and kills the process in week three.

This skill gives an assistant a fixed question to ask - what was acquired, who owns it,
when is it released - and a standard to cite when the answer is "nothing releases it".

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, works the six-step
workflow (inventory, bound, release on error, measure, diagnose, report), and pulls in the
supporting file it needs. The diagnostic commands in `troubleshooting.md` are meant to be
run by a human or by an agent with shell access - this skill's own `allowed-tools` is
restricted to reading, searching, and web lookup.

```text
SKILL.md                        workflow, the eight leak shapes, severity
README.md                       this file
checklist.md                    pre-return verification, grouped by shape
best-practices.md               the eight shapes with vulnerable/fixed pairs
common-mistakes.md              what goes wrong, plus the wrong fixes
troubleshooting.md              runnable diagnosis per runtime
prompts.md                      prompts that produce findings
references/
  owasp-top10-2025.md         Top 10 categories used for resource lifetime
  api-top10-2023.md           API4 and related API categories
  asvs-5.0.md                 V2, V13, V16 and related chapters
  owasp-resource-limits.md    cross-standard reporting map
  cwe-resource-leaks.md       CWE-400, 401, 770, 772, 789
  runtime-memory-tools.md     Python, Node, JVM, Go, container flags
examples/
  README.md                     eight vulnerable/fixed pairs, one per leak shape
```

## Standards Covered

| Standard | What it covers here | Version | Verified |
|---|---|---|---|
| OWASP Top 10 | A06 Insecure Design, A02 Security Misconfiguration | 2025 | 2026-07-28, `owasp.org/Top10/2025/` |
| OWASP API Security Top 10 | API4 Unrestricted Resource Consumption | 2023 | 2026-07-28, `owasp.org/API-Security/` |
| OWASP ASVS | V2 Validation and Business Logic, V13 Configuration, V16 Logging and Error Handling | 5.0.0 (released 2025-05-30) | 2026-07-28, ASVS project page |
| CWE | 400, 401, 770, 772, 789 | current | 2026-07-28, `cwe.mitre.org` |

ASVS citations are chapter level only. For requirement-by-requirement verification, work
from the official ASVS repository.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/architecture/performance/SKILL.md` is readable, or copy the `performance`
directory into `~/.claude/skills/`.

## Example Usage

Review a diff for resource lifetime:

```text
Review my staged changes with skills/architecture/performance. For each acquisition list
the owner and the release point. Report anything with no bound or no release on the error
path, and classify it as L1 to L8.
```

Work an active leak:

```text
Our Python service RSS grows about 40 MB/hour and gets OOMKilled at 2 GB roughly daily.
Walk me through the tracemalloc method in troubleshooting.md, then tell me what a growing
retainer would look like versus a warm cache.
```

Choose a limit rather than accepting a default:

```text
This endpoint accepts a JSON array of IDs and fetches each one. Give me the bounds it
needs - array length, body size, concurrency, timeout - and the reasoning for each number.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not a profiler. It finds missing bounds and missing release paths by
  reading code. It cannot find a leak that only appears under a specific interleaving, in a
  native extension, or inside a third-party library. Pair it with a heap profiler.
- No numbers for your system. Every limit here is illustrative. A cache of 10 000 entries
  is right or wrong depending on entry size and available memory; the skill tells you to
  pick a number and justify it, not which number.
- Cannot confirm runtime configuration. Whether `GOMEMLIMIT` is actually set, whether the
  container limit matches the JVM's view, whether the pool is shared across workers - all
  of that is deployment state, invisible in source.
- Languages are Python, TypeScript/JavaScript (Node and browser), and Go, with Java and C#
  where they teach something the others cannot. Nothing here is Rust, Ruby, or PHP specific.
- Concurrency correctness is out of scope. Deadlocks, races, and lock ordering are
  adjacent, and a bounded queue that deadlocks is worse than an unbounded one. This skill
  tells you to bound the queue and choose block/drop/reject; it does not verify your
  locking.
- Says nothing about CPU profiling, algorithmic complexity, or query plan tuning beyond
  N+1 detection. Those belong in `scalability` and `database-security`.

## Security Notes

This skill contains deliberately broken code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and
paired with a fixed version. Do not copy a labelled-vulnerable block into a project.

Two of the leak shapes are also confidentiality bugs, not just availability ones. L6
(request-scoped state stored globally) and shared-cache-without-tenant-key both serve one
user's data to another - `A01:2025`, not just `A06:2025`. Treat them as data leaks first.

Heap dumps contain live application memory: session tokens, passwords in flight,
decrypted PII. Treat a `.heapsnapshot`, `.hprof`, or `pprof` file as a secret. Do not
attach one to a public issue, and do not leave `--inspect` bound to a public interface -
an open inspector port is remote code execution.

The examples use placeholder values only. No real credentials, hostnames, or personal
data appear in this skill.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- CWE-400 - <https://cwe.mitre.org/data/definitions/400.html>
- CWE-401 - <https://cwe.mitre.org/data/definitions/401.html>
- CWE-770 - <https://cwe.mitre.org/data/definitions/770.html>
- CWE-772 - <https://cwe.mitre.org/data/definitions/772.html>
- CWE-789 - <https://cwe.mitre.org/data/definitions/789.html>
