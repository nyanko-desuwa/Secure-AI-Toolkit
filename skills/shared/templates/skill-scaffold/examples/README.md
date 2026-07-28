# Examples

Vulnerable code next to its fix. One entry per category the skill covers, so a reader can find
the shape of their own bug.

## Entry format

Each entry follows the same four beats:

```markdown
## <Name of the mistake>

`<A0?:2025>` · `<CWE-???>` · ASVS <V?>

<One sentence on where this shows up in real code.>

```<lang>
// Vulnerable: <what the code wrongly assumes>
<minimal code — enough to show the bug, nothing more>
```

<One or two sentences on what the attacker actually does. Concrete: what they send, what
they get back.>

```<lang>
// Fixed: <what changed, in five words>
<the corrected version>
```

Why this works: <the mechanism. Not "it validates input" — say what is now impossible.>

<Optional but valuable: the tempting wrong fix, and why it is weaker. Or a remaining gap.>
```

## What makes an example earn its place

- The vulnerable block is minimal. Framework boilerplate hides the bug.
- The attack is concrete. "An attacker could exploit this" teaches nothing; "increments the ID
  and reads every order" teaches the lesson in one line.
- The `Why this works` line names a mechanism. If the fix removed a branch, say so. If it moved
  the check into the query, say so.
- Wrong fixes are addressed. Readers reach for UUIDs, regex denylists, and client-side
  validation unprompted. Heading that off is most of the value.
- Remaining gaps are stated. The SSRF example in `core/owasp` says outright that it is still
  open to DNS rebinding. That is the standard to hold, not an exception.

## Language

Pick whatever shows the bug most plainly — the mistake is the subject, the syntax is
incidental. `core/owasp` mixes Python, JavaScript, Java, and PHP for that reason. Do not
translate one example into five languages.

## Safety

Every vulnerable block starts with a `// Vulnerable:` or `# Vulnerable:` comment on the first
line, so a snippet stays labelled after it is copied out of context.

Placeholder values only. No real credentials, hostnames, keys, or personal data.

## Worked example

`skills/core/owasp/examples/README.md` — seven pairs in one file. Single-file works while the
count is small; split into one file per category past roughly ten.
