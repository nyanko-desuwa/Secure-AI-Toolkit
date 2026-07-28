# Prompt Examples

Prompts that get useful output from this skill. Each one states the scope, the standard, and
the expected shape of the answer — vague prompts produce category recitals instead of findings.

## Review a diff

```
Review my staged changes against OWASP Top 10 2025. For each finding give the category,
file:line, why it is exploitable, and the fix. Skip categories that do not apply.
```

Why it works: bounds the input (staged changes), names the standard, and asks for an
exploitation path. That last part is what separates a finding from a code smell.

## Review one file in depth

```
Read src/api/invoices.py and check every handler for broken object level authorization
(A01, API1:2023). Show me which queries are scoped to the actor and which are not.
```

Naming the single category keeps the answer concrete. Asking for both the safe and unsafe
cases forces an actual read rather than a pattern-match on keywords.

## Design review before code

```
I am adding an endpoint that lets users export their own data as a CSV. Before I write it,
what controls does it need? Map each to a Top 10 category and an ASVS requirement.
```

Design-time prompts are cheaper than review-time ones. Export endpoints in particular tend
to need A01 (scoping), A06 (rate limiting), and ASVS V5 if a file lands on disk.

## Threat model a feature

```
Threat model the password reset flow in this repo. Cover the token lifecycle, enumeration,
and what happens if the mail provider is down. Assume the attacker knows a victim's email.
```

Stating the attacker's starting knowledge is what makes the output specific. Without it you
get a generic list.

## Verify before returning code

```
Run the OWASP checklist against the change we just made. Mark each item pass, fail, or not
applicable with a reason. Do not mark anything pass that you have not actually checked.
```

The last sentence matters. Ask for honest gaps or you get a wall of checkmarks.

## Map a finding to standards

```
This handler builds a SQL string with an f-string. Give me the Top 10 category, the CWE,
the ASVS requirement it violates, and a severity with your reasoning.
```

## Explain a control you disagree with

```
You said to return 404 instead of 403 for objects the user does not own. Our API docs
promise 403 on permission failure. Which should win, and what breaks either way?
```

Conflicts between a standard and a project constraint are normal. See
[troubleshooting.md](troubleshooting.md) for how they get resolved.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is this code secure?" | No scope. Produces a checklist, not findings |
| "Fix all the vulnerabilities" | Invites speculative rewrites of working code |
| "Make this OWASP compliant" | There is no compliance certificate for Top 10. Ask for specific controls |
| "Add security" | Adds defensive noise instead of the one control that matters |
