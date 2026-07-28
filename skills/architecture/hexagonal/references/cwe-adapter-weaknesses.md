# CWE entries used in this skill

Every title below was read from `cwe.mitre.org` on 2026-07-28. Titles are reproduced as published;
abstraction levels are noted because a Class-level entry is a weaker mapping than a Base-level one
and reviewers should know which they are getting.

No CVE is cited anywhere in this skill, and no CWE version number is asserted.

## Access control and boundary placement

| ID | Title | Abstraction |
|---|---|---|
| CWE-602 | Client-Side Enforcement of Server-Side Security | Class |
| CWE-653 | Improper Isolation or Compartmentalization | Class |
| CWE-1220 | Insufficient Granularity of Access Control | Base |
| CWE-488 | Exposure of Data Element to Wrong Session | Base |

CWE-602 is the second-adapter failure. The name says client-side, and the weakness is broader: a
security decision delegated to a component the server cannot vouch for. An HTTP handler that owns
the ownership check while a queue consumer calls the same use case is the same shape — the
enforcement lives somewhere the other callers are not.

CWE-653 is what a transport type in a core signature costs you. Once the core reads a header, the
compartment is gone and the adapter is no longer a boundary.

CWE-1220 is the "system actor can do everything" outcome. One coarse role for all background work
means the port's check passes for operations the job never needed.

CWE-488 is the singleton adapter holding a request-scoped actor, tenant, or connection. Note the
title: it is data exposed to the wrong session, not a leak of memory. The cross-tenant read is the
primary finding; the retained graph is secondary.

## Input, injection, and untrusted responses

| ID | Title | Abstraction |
|---|---|---|
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | Base |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | Base |
| CWE-918 | Server-Side Request Forgery (SSRF) | Base |
| CWE-502 | Deserialization of Untrusted Data | Base |

CWE-89 is what a driven port that accepts a query fragment, sort expression, or filter string
reintroduces. The port hides it, which is worse than exposing it.

CWE-915 is the mass-assignment consequence of reusing a core type as the wire type. The adapter's
inbound DTO is the allowlist.

CWE-918 is the outbound adapter for a user-influenced URL. The page lists XSPA and Cross Site Port
Attack as alternate names.

CWE-502 is why a third-party response is parsed into a schema and never fed to a deserializer that
can instantiate types.

## Error handling

| ID | Title | Abstraction |
|---|---|---|
| CWE-209 | Generation of Error Message Containing Sensitive Information | Base |

The finding for a domain or driver exception rendered verbatim by an inbound adapter. The core
returns typed errors; the adapter maps them to a stable code and logs the detail.

## Resources and lifetime

| ID | Title | Abstraction |
|---|---|---|
| CWE-772 | Missing Release of Resource after Effective Lifetime | Base |
| CWE-401 | Missing Release of Memory after Effective Lifetime | Variant |
| CWE-770 | Allocation of Resources Without Limits or Throttling | Base |
| CWE-400 | Uncontrolled Resource Consumption | Class |

CWE-772 covers the adapter that opens a connection, file handle, or client per call and never
closes it, and the port that returns a cursor or stream nobody closes because the core does not
know it exists.

CWE-401 is the accumulating subscription: a handler registered on every reconnect, each closure
retaining the use case and its dependencies. The page notes "Memory Leak" as an alternate term and
discourages it because it is also used for memory disclosure. Prefer the full title in a report.

CWE-770 is the in-memory adapter used as a cache with no bound or eviction, and the unbounded
queue between an inbound adapter and the core.

CWE-400 is the Class-level parent — resource exhaustion. Use it when the specific mechanism is not
one of the above, and prefer the Base-level entry when it is.

Heap-level diagnosis for all four is `skills/architecture/performance/`, which owns memory-leak
detail in this repository. This skill names the structural cause and hands over.

## Verification notes

- Each title above was fetched individually from its `cwe.mitre.org/data/definitions/<id>.html`
  page on 2026-07-28.
- Abstraction levels are as stated on those pages. CWE-401 is a Variant, so pair it with CWE-772
  when reporting an adapter that retains handles as well as memory.
- Several entries have been renamed by MITRE in the past. If you quote a title in a report, re-read
  the page rather than copying from an older document.
