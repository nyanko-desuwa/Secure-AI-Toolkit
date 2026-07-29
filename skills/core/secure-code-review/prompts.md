# Prompt Examples

Prompts that produce findings instead of a category recital. Every one of them bounds the
input, names the sink or the standard, and asks for the exploitation path. That last part is
the whole difference: without it you get a list of things that look wrong.

## Review a diff

```
Review the diff against origin/main. Hunt by sink, not by reading top to bottom. For each
candidate, try to disprove it before reporting: can the source be attacker-controlled, is
there a control in between, and can you write the request that triggers it? Report findings
and observations in separate lists.
```

The disprove instruction is doing the work. Without it a model reports every f-string near a
`SELECT`, including the ones where the input is an integer from a path converter.

## Review one weakness class across a codebase

```
Search src/api for object lookups by ID - findUnique, findById, .get(pk). For each one, tell
me whether the query is scoped to the acting user or whether ownership is checked separately
afterwards. List the ones with no scoping at all first.
```

Asking for both the safe and unsafe cases forces a real read. Asking only for problems
invites pattern-matching on keywords.

## Trace one candidate to a verdict

```
Trace `sort` in src/reports/export.py:88 back to its entry point. Show me every function it
passes through and what validates or transforms it. Then tell me whether it is exploitable
and what the concrete input would be.
```

Use this for the single finding that matters rather than a broad sweep. The chain of
functions is the evidence; without it, "exploitable" is an assertion.

## Triage a scanner result

```
Semgrep flagged src/reports/export.py:88 as SQL injection, rule
python.lang.security.audit.formatted-sql-query. Confirm or refute it. If it is a false
positive, tell me exactly what stops the attack and whether that control is load-bearing or
incidental.
```

The last clause matters. A finding stopped by an incidental control - an int cast that exists
for formatting reasons - is a smell worth reporting, because the next refactor removes it.

## Review AI-generated code

```
This handler was generated. Before anything else check the four AI failure modes: auth check
in the wrong layer, validation without encoding at the sink, fail-open catch around a
security decision, and calls to library options that do not exist in the pinned version.
Verify every library call against package-lock.json.
```

Version-checking is the step humans skip. A `verify(token, { algorithm: "HS256" })` - singular
key where the library reads `algorithms` - silently accepts any algorithm.

## Assign severity to someone else's finding

```
Here is a reported finding: [paste]. Rate it using exploitability times blast radius. State
the deployment context you are assuming and how the rating changes if I tell you it is
internal-only. Give a CVSS v4.0 Base vector as well, and say what the vector cannot capture.
```

Asking for the pivot condition gets you a rating you can act on when the assumption turns
out wrong.

## Pick the CWE

```
This code interpolates a client-supplied tenant ID into an authorization check. Give me the
specific CWE with its name, the OWASP Top 10 2025 category, the ASVS 5.0 chapter, and why
that CWE beats the two nearest alternatives.
```

The comparison forces specificity. Left open, everything access-control-shaped becomes
CWE-284.

## Propose the fix and prove it

```
Fix the BOLA in src/api/orders.ts:41. Change only what the vulnerability needs - no
refactoring of the surrounding handler. Then write a regression test that fails against the
current code and passes after the fix, asserting on the response, not on internals.
```

"Fails before, passes after" is the only definition of a regression test that means anything.
A test written against the fixed code usually passes against the vulnerable code too.

## Ask what the review missed

```
You reviewed the API layer. What did you not review, and what weakness classes could hide
there? Be specific about files, not categories.
```

Coverage gaps are findings. This prompt surfaces them instead of leaving the reader to assume
the whole repo was read.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is this code secure?" | No scope, no sink. Produces a checklist recital |
| "Find all vulnerabilities" | No disprove step, so every candidate is reported. High false-positive rate |
| "Review this file for OWASP Top 10" | Ten categories, most irrelevant. Name the two that apply |
| "Fix the security issues" | Invites a rewrite. Ask for the minimal change per finding |
| "Rate this critical or not" | Severity without context is guesswork. State deployment and blast radius |
| "Add input validation" | Validation is not the control for most sinks. Encoding is |
| "Make it OWASP compliant" | There is no Top 10 compliance state. Ask for named controls |
| "Is this exploitable?" with no code | Cannot be answered. Paste the sink and its caller |
