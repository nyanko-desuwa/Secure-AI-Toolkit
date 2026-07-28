# CWE Entries for Resource Leaks

The five weaknesses this skill cites. Verified 2026-07-28 against <https://cwe.mitre.org>.

Only these five. If a finding needs a different CWE, look it up at cwe.mitre.org first — a
plausible-looking number that turns out to be about something else discredits the whole
report.

| CWE | Name | The distinction that matters |
|---|---|---|
| CWE-400 | Uncontrolled Resource Consumption | The outcome. The system does not control how much of a resource is consumed |
| CWE-401 | Missing Release of Memory After Effective Lifetime | Memory specifically, still held after it is no longer needed |
| CWE-770 | Allocation of Resources Without Limits or Throttling | No cap on the allocation in the first place |
| CWE-772 | Missing Release of Resource after Effective Lifetime | Any resource — handle, socket, connection, lock — not released |
| CWE-789 | Memory Allocation with Excessive Size Value | One allocation whose size comes from untrusted input |

## Picking between them

The three that get confused are 400, 770, and 401/772.

CWE-770 is the missing bound. Ask: is there a maximum? If no, 770 applies regardless of
whether anything is released.

CWE-401 and CWE-772 are the missing release. Ask: does the code let go of it when it is done?
Use 401 when the resource is memory and 772 when it is a handle, socket, connection, cursor,
timer, or lock. They overlap for objects that hold both; cite 772 when the scarce thing is the
handle and 401 when it is the bytes.

CWE-400 is the consequence, and it is the right citation when the mechanism is not a single
missing bound or release — a retry storm, an algorithmic blow-up, a queue that grows because
the consumer is slow. In a chain, MITRE treats 770 and 401 as ways to reach 400. Citing 400
alone reads as vague; citing 400 alongside the specific mechanism reads as complete.

CWE-789 is narrower than it looks. It is one allocation sized by input — `malloc(n)` where the
caller chose `n`, `bytearray(header_length)`, a buffer preallocated from a declared content
length. Not a loop that allocates many small objects; that is 770.

## Mapping to the leak shapes

| Shape | Primary | Secondary |
|---|---|---|
| L1 Unbounded cache | CWE-770 | CWE-401 |
| L2 Listener accumulation | CWE-401 | CWE-772 |
| L3 Connection and handle exhaustion | CWE-772 | CWE-400 |
| L4 Timer and background task leaks | CWE-772 | CWE-400 |
| L5 Closure capture and retention | CWE-401 | — |
| L6 Request-scoped state stored globally | CWE-401 | see also A01:2025 |
| L7 Large payload read fully into memory | CWE-770 | CWE-789 |
| L8 Unbounded queue or buffer | CWE-400 | CWE-770 |

L2 gets 401 rather than 772 because what actually grows is the retained closure graph; the
subscription itself is cheap. L3 gets 772 because the scarce resource is the connection slot
on the database, and it runs out long before your heap does.

## Why a garbage collector does not remove 401

CWE-401 is usually taught with `malloc` and no `free`, which makes it look like a C-only
weakness. It is not. The definition is memory not released after its effective lifetime, and a
managed runtime releases only what is unreachable. A cache entry nobody will ever read again
is reachable, so it is never freed. The mechanism changed from a lost pointer to a live
reference; the weakness did not.

This matters when a reviewer objects that "Python cannot leak". The answer is that the leak is
a reachable object nobody wants, and reachability is decided by your code, not by the
collector.

## Related weaknesses, deliberately not cited

Named here so nobody has to guess whether they were forgotten:

- Uncontrolled recursion and stack exhaustion. Real, and a different skill's material.
- Decompression bombs. The [checklist](../checklist.md) asks for an output size bound; the
  weakness has its own CWE, which is not in this skill's verified set.
- Regular-expression denial of service. Belongs with input validation.
- Deadlock and race conditions. Adjacent to bounded queues and out of scope; a bounded queue
  that deadlocks is worse than an unbounded one, and this skill does not verify your locking.

If a report needs one of these, verify the number before writing it down.

## Using a CWE in a report

Attach it to the mechanism, not to the symptom. "OOMKilled, CWE-400" says nothing actionable.
"`asyncio.Queue()` with default `maxsize=0` at `ingest.py:31`, producer at request rate,
consumer at 200/s — CWE-400 via CWE-770" names the bound that is missing and where.

One CWE plus one OWASP category is enough. A finding tagged with five identifiers looks
generated rather than investigated.

## Sources

- CWE-400 — <https://cwe.mitre.org/data/definitions/400.html>
- CWE-401 — <https://cwe.mitre.org/data/definitions/401.html>
- CWE-770 — <https://cwe.mitre.org/data/definitions/770.html>
- CWE-772 — <https://cwe.mitre.org/data/definitions/772.html>
- CWE-789 — <https://cwe.mitre.org/data/definitions/789.html>
