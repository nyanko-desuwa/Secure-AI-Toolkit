# The Review Process

The five-step workflow in depth, with its mapping to the OWASP Code Review Guide.

Source: <https://owasp.org/www-project-code-review-guide/>
Version: 2.0, July 2017. Checked 2026-07-28.

The Guide is the only published OWASP process reference for manual code review. Its
vulnerability chapters are built on the Top 10 2013 and are out of date — Injection was A1
then, and there was no supply chain category. Its process material is not out of date: how to
scope a review, who does it, and why a scanner does not replace a reader all still hold. Take
process from the Guide, categories from Top 10 2025.

## Why a fixed order

An unordered review reads top to bottom and reacts to whatever is visible. That produces two
failures. It over-reports the visible (a hardcoded test password on line 4) and under-reports
the invisible (the missing authorization check, which is an absence and has no line number).

A fixed order forces both. The sink hunt finds absences because you enumerate the sinks that
should have a control and check each one, rather than reading until something looks wrong.

## Step 1 — Scope

Write down four things before opening a file.

| Item | Why it matters |
|---|---|
| Boundary | A diff, a directory, or one weakness class repo-wide. Mixing them means finishing none |
| Deployment context | Internet-facing, internal, or CLI. Moves severity by two rows |
| Actors | Anonymous, authenticated user, tenant admin, platform admin, service account |
| Out of scope | Named explicitly. Infrastructure, dependencies, the frontend, whatever you skipped |

The Guide is direct on the point that a review needs a defined scope agreed in advance,
because the alternative is an open-ended read that stops when the reviewer gets tired.

Diff reviews have a specific trap. The diff is not the change — the change is the diff plus
everything it now calls. If a changed line calls `get_document(doc_id)`, open that function.
One level out from every changed line, minimum. Two if the first level is a thin wrapper.

## Step 2 — Map trust boundaries

A trust boundary is where data changes owner. You are producing a source-to-sink list, not a
diagram.

Sources, in rough order of how often they are forgotten:

1. Route parameters and query strings. Nobody forgets these
2. Request bodies, including nested objects and array elements
3. Headers. `Host`, `X-Forwarded-For`, `Referer`, `Content-Type`, custom tenant headers
4. Cookies, including ones set by other subdomains
5. Uploaded file names, declared types, and contents
6. Webhook payloads. Frequently treated as trusted because they come from a partner
7. Message queue and event payloads. The producer may be another team's untrusted input
8. Database rows that originally came from a user. Stored XSS lives here
9. Environment and config in a multi-tenant deploy
10. LLM output, when it is fed into a sink. Model output is untrusted input

Then the four questions that decide whether the boundary holds:

- Where is the actor identity established, and from what? A session, a token, or a header?
- Where is the authorization decision made? Route, service, or query? Only the last is hard
  to forget
- Where does internal code stop validating because "it is internal"? That is the trust
  downgrade, and it is where a second-order injection lands
- What leaves the process? Outbound HTTP, DB write, file write, shell, log line, response body

Anything with no path from an untrusted source to a sink is not a vulnerability. Write it in
observations if it is worth saying, and move on.

## Step 3 — Hunt by sink

Sink-first, not source-first. Sinks are a short greppable list; sources are everything. See the
sink table in [../SKILL.md](../SKILL.md#3-hunt-by-sink).

Method for each hit:

1. Grep the sink pattern across scope
2. For each hit, read the enclosing function and identify every parameter that reaches the sink
3. Walk backwards to the entry point. Stop when you reach a route, a consumer, or a literal
4. Note what control you passed on the way — validation, cast, allowlist, ORM
5. Decide: reachable with attacker-controlled data, or not

Absences need their own pass, because grep does not find missing code. Three specific sweeps:

- Every route handler in scope: does it have an authorization decision, and where?
- Every object lookup by ID: is the actor part of the query?
- Every `catch` around a security decision: what does it return?

## Step 4 — Verify adversarially

The step that decides whether the report is trusted. For each candidate, argue against
yourself. Five questions, all of which must survive:

1. Is the source actually attacker-controlled? Read the caller. A function taking a `path`
   parameter is not path traversal if every caller passes a literal
2. Is there a control in between? A middleware, a validator, an ORM, a column type, a
   framework default. Check the version and the config — not the framework's reputation
3. Does the sink behave as you assume? `cursor.execute(sql, params)` is safe;
   `cursor.execute(sql % params)` is not. `textContent` is not `innerHTML`. Read the API docs
   for the pinned version
4. What preconditions does exploitation need? Admin role, a race window, a specific DB
   engine, a non-default config. Each one lowers severity. State them
5. Can you write the request? A concrete method, path, and body. If you cannot, you have a
   smell

Record the disproof attempt for anything you drop. "Checked, `sort` is validated against an
allowlist in the caller at line 40" is worth more to the next reviewer than silence, and it
stops the same false positive being re-reported.

## Step 5 — Report

Findings and observations in separate lists, with separate counts.

A finding has: title, location, sink, source, CWE, Top 10 category, ASVS chapter, a concrete
exploit input, impact, severity with reasoning, minimal fix, and a regression test that fails
before the fix.

An observation has one line. No severity, no CWE unless it is obvious, no fix demanded.

Also report coverage. What you reviewed, what you skipped, and what you could not verify from
code. A review that does not say what it missed implies it missed nothing.

## What manual review catches that scanners do not

Worth knowing so the review targets its strength:

- Missing authorization. A scanner sees code that is present. An absent check has no pattern
- Wrong-layer controls. The check exists, passes a linter, and runs on the client
- Business logic. Negative quantities, rounding, workflow steps done out of order
- Fail-open error handling. Syntactically fine, semantically inverted
- Chains. Three mediums that compose into account takeover

And the reverse, which is why the Guide argues for both: scanners beat readers on coverage,
consistency, and anything requiring cross-file taint tracking through a framework.

## Sources

- OWASP Code Review Guide 2.0 (July 2017) — <https://owasp.org/www-project-code-review-guide/>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 — <https://owasp.org/www-project-application-security-verification-standard/>
