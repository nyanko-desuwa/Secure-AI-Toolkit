# Shared Prompts

Prompts that work across skills. Each skill has its own `prompts.md` with domain-specific
wording; this file holds the framing that makes any of them produce findings instead of recitals.

The difference between a useful answer and a category recital is almost always in the request.
"Review this for security" gets you the Top 10 read back at you. Naming the standard, demanding
an exploitation path, and asking what could not be verified gets you something reviewable.

## The four moves

Every prompt below is built from these. They compose.

**Name the standard and the version.** Without it an assistant answers from whichever edition it
recalls, and recalled category IDs are wrong more often than they look. `A03` means Injection in
2021 and Software Supply Chain Failures in 2025.

**Demand an exploitation path.** A finding with concrete inputs and a stated outcome is a
vulnerability. Without one it is a code smell, and mixing the two is what makes people ignore
security output.

**Ask what was not checked.** This is the highest-value sentence in any security prompt. It
converts silent assumptions into a stated list you can act on.

**Forbid the padding.** Say explicitly that a short list is an acceptable answer. Otherwise you
get filler ranked as High.

## Review an existing change

```text
Review the diff against OWASP Top 10 2025 and ASVS 5.0. For each finding give:
category (Top 10 ID + ASVS chapter + CWE if one applies), file:line, the concrete input or
state that exploits it, the fix and why it closes the hole rather than looking safer, and
severity with reasoning.

Skip anything with no exploitation path, or label it explicitly as a code smell.
Then list what you could not verify from the source alone.
```

Scoped narrower when you know where to look:

```text
In src/api/invoices.py, every handler that loads a record by an ID from the request:
show me the query and tell me whether the tenant filter is applied in the query itself or
after the fetch. Quote the lines.
```

That second one matters because fetch-then-check and scoped-query look equally fine in a
summary and are not equally safe.

## Design review, before the code exists

Cheaper than reviewing it afterwards, and the only point where you can still change the shape.

```text
I am adding an endpoint where a user exports their own data as CSV.
Before any code: what controls does it need? Map each to a Top 10 2025 category and an ASVS
chapter. Include the limits — pagination, row cap, timeout, rate limit — and say what happens
when each one is absent. Name the failure mode, not the principle.
```

## Verify generated code before accepting it

```text
Run skills/shared/checklists/README.md plus every skill checklist that applies to this diff
against the change. Output pass, fail, or n/a per item with the file:line you checked.
n/a needs a reason. Do not mark pass on anything you did not read.
List which skills you loaded and which you decided did not apply, with why.
```

Then the follow-up that catches the rest:

```text
Which items did you mark pass without being able to confirm them from source? Anything that
depends on runtime config, deployment state, or a value set outside this repository.
```

## Route to the right skills

Assistants pick one skill and stop. This forces the full set.

```text
Read skills/shared/checklists/README.md and the routing table in AI_INSTRUCTIONS.md.
For this change, list every skill that applies and why. Then load them and review.
If a skill you need is In progress or empty, say so and name what it would have covered
instead of filling the gap from memory.
```

## Disprove your own findings

```text
For each finding you just reported, try to disprove it. What precondition does it need that
you have not verified? If a caller could already be sanitising the value, say so and lower
your confidence instead of asserting certainty.
```

This trims false positives faster than any amount of extra review, and it surfaces the
unverified preconditions rather than hiding them inside a confident sentence.

## Explain it to the person who has to decide

For a requester who does not read code. The technical answer is not the deliverable here — the
consequence is.

```text
Explain each finding in two sentences with no jargon: what someone could do, and what it
would cost. Then the technical detail underneath.
```

"Any visitor to your site could read this key and spend your API credits" lands where "the key
is exposed in the client bundle" does not.

## Anti-patterns

These read like reasonable requests and produce unreviewable output.

| Prompt | What you get | Instead |
|---|---|---|
| "Is this secure?" | Yes, with caveats. Unfalsifiable. | Name the standard and ask for findings with exploitation paths. |
| "Review this for security" | The Top 10 recited back, loosely attached to your code. | Scope to files and categories. |
| "Find all vulnerabilities" | Padding ranked High to look thorough. | "Skip anything without an exploitation path. A short list is fine." |
| "Fix the security issues" | Edits with no explanation of what was wrong. | Ask for the finding first, apply the fix second. |
| "Make it OWASP compliant" | There is no such thing. Top 10 is a risk ranking. | "Implement the ASVS V-chapter requirements, report with Top 10 categories." |
| "Add input validation" | A regex denylist at one call site. | "Allowlist at the boundary, encode at the sink. Show both." |
| "Add rate limiting" | An in-memory per-IP counter that does nothing behind four pods. | Ask for the dimensions, the shared store, and the behaviour when that store is down. |
| "Use UUIDs so IDs cannot be guessed" | Unguessable IDs, unchanged authorization. | "Scope the query by the acting subject." Unguessability is not a control. |
| "Sanitize the input" | One escaping call, wrong layer. | Name the sink. Escaping for HTML does not make a query safe. |
| "Does this follow best practices?" | Generic agreement. | Ask which specific requirement, and where it is enforced. |

## Prompts that ask for something this toolkit will not produce

Refuse and say why, rather than producing a weakened version:

- Working exploit code, payload lists, or wordlists
- Credential stuffing, spraying, or scanning automation, including "just to test my own login"
- Detection or WAF evasion techniques
- "Brute-force this endpoint to see if the limiter works" — assert the limiter engages with a
  synthetic account and one fixed wrong candidate instead

A test that proves a control engages is defensive. A tool that finds valid credentials is not,
and the distinction does not change because the target is yours.
