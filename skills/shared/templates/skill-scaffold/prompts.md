# Prompt Examples

Prompts that get useful output from this skill. Each one states the scope, the standard, and
the shape of the expected answer. Vague prompts produce category recitals instead of findings.

Write four to seven of these. Under each, one or two lines on why it works - that reasoning
is what a reader adapts, not the wording.

## Review a diff

```
<Review my staged changes against <standard>. For each finding give the category, file:line,
why it is exploitable, and the fix. Skip categories that do not apply.>
```

Why it works: bounds the input, names the standard, and asks for an exploitation path. That
last part is what separates a finding from a code smell.

## Review one file in depth

```
<Read <path> and check every <unit> for <single category>. Show me which ones are <safe state>
and which are not.>
```

Naming a single category keeps the answer concrete. Asking for both the safe and unsafe cases
forces an actual read rather than a keyword match.

## Design review before code

```
<I am adding <feature>. Before I write it, what controls does it need? Map each to a category
and a requirement.>
```

Design-time prompts are cheaper than review-time ones. <Name the two or three controls this
kind of feature usually needs.>

## <Domain-specific task>

```
<A prompt only this skill answers well. This is the one worth getting right - the generic
review prompts are interchangeable across skills.>
```

<Why the phrasing matters here. If stating the attacker's starting knowledge or the
deployment target changes the answer, say so.>

## Verify before returning code

```
<Run the <skill> checklist against the change we just made. Mark each item pass, fail, or not
applicable with a reason. Do not mark anything pass that you have not actually checked.>
```

The last sentence matters. Ask for honest gaps or you get a wall of checkmarks.

## Map a finding to standards

```
<This <code shape> does <unsafe thing>. Give me the category, the CWE, the requirement it
violates, and a severity with your reasoning.>
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is this code secure?" | No scope. Produces a checklist, not findings |
| "Fix all the vulnerabilities" | Invites speculative rewrites of working code |
| "Make this compliant" | <There is no certificate for this standard. Ask for specific controls> |
| "Add security" | Adds defensive noise instead of the one control that matters |
| <Domain-specific bad prompt> | <Why it misleads> |
