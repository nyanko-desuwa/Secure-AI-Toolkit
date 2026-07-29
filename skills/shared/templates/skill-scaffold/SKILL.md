---
name: <skill-name>
description: '<One line on what this skill decides. Triggers: "keyword", "keyword", "từ khoá".>'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# <Skill Name>

<One or two sentences. What decisions does this skill make, and at what point in the work?>

## When to Use

- <Writing code that touches ...>
- <Reviewing ... for ...>
- <Designing ...>
- <Mapping a finding to a standard>

## Ownership Boundary

**Owns:** <The trust or service boundary this skill is the primary owner for.>

**Does not own:**

| Concern | Route to |
|---|---|
| <Adjacent decision this skill must not duplicate> | `<canonical-skill-name>` |

The catalog `ownership` object is canonical. Keep this table aligned with its `non_goals` owners.

## Standards This Skill Maps To

| Standard | Use it for | Version here |
|---|---|---|
| <Top 10 2025> | <Risk triage> | <2025> |
| <ASVS 5.0 V?> | <Verification> | <5.0.0> |

State what each standard is for, not just that it exists. See [references/](references/).

## Workflow

### 1. Scope

<Three questions that must be answerable before writing code. If they cannot be answered,
read the code first.>

### 2. Map

<Pick the relevant categories rather than reciting all of them. Give an example of a
correct mapping and one common miscategorisation.>

### 3. Apply Controls

1. <Control, ordered by what fails hardest if missing>
2. <...>

Link into [best-practices.md](best-practices.md) rather than repeating patterns here.

### 4. Verify

Run [checklist.md](checklist.md) before returning code. Every unchecked box is either a fix
or a stated limitation.

### 5. Report

For each finding: category, location, why it is exploitable, and the fix. A finding without
an exploitation path is a code smell, not a vulnerability. Say which it is.

## Severity

Rank by exploitability and blast radius, not by category name.

- **Critical** - <...>
- **High** - <...>
- **Medium** - <...>
- **Low** - <...>

## Related Skills

- `<skill>` - <when to reach for it instead>

## Supporting Files

- [README.md](README.md) - purpose, configuration, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns that hold up
- [common-mistakes.md](common-mistakes.md) - what goes wrong, with fixes
- [troubleshooting.md](troubleshooting.md) - when the guidance conflicts
- [prompts.md](prompts.md) - prompt examples
- [references/](references/) - standard summaries with source links
- [examples/](examples/) - vulnerable and fixed code side by side
