# Skill Templates

Starting point for a new skill. Copy `skill-scaffold/` into the right category directory,
rename it, and fill in the placeholders.

```bash
cp -r skills/shared/templates/skill-scaffold skills/core/api-security
```

## What a finished skill looks like

Eleven files. Seven at the top level, plus `references/` and `examples/`:

```text
skills/<category>/<skill-name>/
├── SKILL.md              entry point: frontmatter, workflow, severity rules
├── README.md             purpose, how it works, configuration, limitations
├── checklist.md          pre-return verification, grouped by category
├── best-practices.md     patterns, each with a vulnerable/fixed pair
├── common-mistakes.md    what goes wrong, and why the fix works
├── troubleshooting.md    what to do when the guidance conflicts
├── prompts.md            prompts that produce findings, and anti-patterns
├── references/           standard summaries, version-pinned with a check date
└── examples/             vulnerable and fixed code side by side
```

Eleven is the floor, not the target. `references/` holds one file per standard plus its own
`README.md` index, so a skill citing four sources has more files than one citing two -
`core/publish-safety/` has thirteen. What matters is that every entry in the tree above exists and
none of them is a stub.

`skills/core/owasp/` is the worked example. Read it before starting - it is easier to match
than to describe.

## The bar

A skill is not done because the files exist. It is done when:

- Every control cites a standard. Top 10 category, ASVS chapter, and CWE where one applies.
  A control with no citation is an opinion, and opinions do not survive review.
- Every pattern shows both states. Vulnerable code, fixed code, and a sentence on why the
  fix closes the hole rather than just looking safer.
- Limitations are stated. If a control has a known gap, name it. The SSRF example in
  `core/owasp/examples/README.md` says outright that it is still open to DNS rebinding -
  that honesty is the point, not a flaw in the example.
- Version-specific claims carry the source URL and the date checked. Category IDs move
  between editions.
- Nothing is invented. If you cannot verify a requirement number, fetch the source or leave
  it out.

## Writing style

Match `core/owasp`. Short sentences, no hype, no filler headers. Prose for reasoning, tables
for lookups, code for patterns. Say the thing and move on.

Two habits worth copying:

- Lead with the failure, not the theory. "Any logged-in user increments the ID and reads
  every order" beats a paragraph on the principle of least privilege.
- Explain why the wrong fix is wrong. Readers reach for UUIDs and regex denylists on their
  own; a skill earns its keep by heading that off.

## Content policy for new skills

These apply to any skill added or substantially rewritten from now on. Existing skills are not
being retrofitted - a sweep across 47 skills would produce a large diff and no new guidance, and
the ones already written meet the bar above. So this section describes the shape of the next skill,
not a debt against the current ones.

### `examples/README.md` - at least seven pairs

Three that are vulnerable in a way a reader would plausibly write, three that are secure by
construction rather than by remembering a check, and one drawn from a real failure mode with the
cost stated. Every pair carries its category and CWE on the heading line. Every vulnerable block is
labelled `Vulnerable:` on its first line, and the fix is in the same section - not in another file,
not implied.

### `prompts.md` - four tiers

| Tier | Written for | Shape |
|---|---|---|
| Beginner | Someone who cannot audit the answer | Names the outcome in plain language, asks for the reasoning back in the same |
| Developer | Someone building the thing | Names the file, the framework, and the constraint |
| Review | Someone checking finished work | Asks for findings in the output contract, with severity reasoning |
| Audit | Someone answering to an auditor | Asks for the standard, the requirement, and the evidence per control |

Plus the anti-pattern table: the prompt that produces a reassuring non-answer (`"is this secure?"`)
next to the one that produces a finding.

### `SKILL.md` - routing and ownership boundaries

`When NOT to Use` has two columns: the request shape that looks like this skill, and the skill
that actually owns it. This is the highest-value paragraph in the file. A skill that cannot say
what it does not cover gets loaded for everything, which is how the loading budget in
`AI_INSTRUCTIONS.md` gets blown.

Also complete `## Ownership Boundary`: one specific boundary the skill owns, then the standard
`Does not own` table. The catalog is canonical: its `ownership.owner_boundary`,
`protected_assets`, and `non_goals` fields must match the owner IDs in the table. Do not repeat
`related` or `loads` as new metadata; they already describe the canonical graph.

A new skill needs all three mandatory conditions - a clear owner boundary, routing path, and
non-goals - plus at least three of: distinct assets, attack surface, verifiable workflow, primary
standards, or lifecycle. Otherwise expand an existing owner skill instead of adding a directory.

### `checklist.md` - tier every item

Every verification item (`- [ ]` / `- [x]`) leads with a tier tag: `[critical]`,
`[recommended]`, or `[optional]`. The router loads critical checks first when context is tight,
so the tag is what makes a checklist usable under a token budget, not just readable.

- `[critical]` - skipping it leaves an exploitable vulnerability or a broken security control
  (access control, injection, secrets, crypto correctness, authentication).
- `[recommended]` - defense-in-depth or hardening most applications should have; its absence is a
  weakness, not usually a direct exploit.
- `[optional]` - context-dependent or a refinement; apply when the situation calls for it.

If everything looks `[critical]`, the tiers are not being used - reserve it for checks whose
failure is a real vulnerability. The validator fails a Ready skill whose checklist has an untiered
item.

### Framework and platform coverage, named

State which stacks the guidance was written against and which it only reaches by analogy. A reader
whose framework is in the second group needs to know that the reasoning transfers and the exact
field names do not. Vague coverage claims are worse than narrow ones.

### `references/` - one file per source

Standard name, version, release date if published, the URL you fetched, and the date you checked
it. Only what the skill uses; a reference file is not a mirror of the standard. What you could not
verify is named, not filled in from memory - a document behind a registration wall is a stated gap,
and the gap is the honest output.

New skills also add their row to `skills/shared/references/skill-graph.md` and
`skills/shared/references/standards-matrix.md`. Both are central tables, so the skill's own
frontmatter carries no dependency metadata.

### Versioning and deprecation

A skill's guidance is dated by its `references/` check dates, not by a version number of its own -
the repository version in `CHANGELOG.md` covers the pack. If a skill's advice becomes wrong because
a standard moved, update the reference file and the pin in all three places
(`references/`, `AI_INSTRUCTIONS.md`, root `README.md`) in the same change. If a skill is
superseded, leave the directory in place with a pointer at the top of `SKILL.md` naming the
replacement, and say so in `CHANGELOG.md`. Deleting a skill breaks every prompt that names its
path.

## Frontmatter

`SKILL.md` needs YAML frontmatter for Claude Code. Other assistants ignore it.

```yaml
---
name: skill-name
description: 'One line on when to use this. Triggers: "keyword", "keyword", "từ khoá".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---
```

Keep `allowed-tools` on the `research-only` profile from `catalog/skills.json`. These skills
read and advise; they must not request `Write`, `Edit`, or arbitrary shell. Include Vietnamese
trigger words alongside English ones. After editing frontmatter, run
`python scripts/validate_repository.py --write-frontmatter`.

## Checklist for a new skill

- [ ] All eleven files present, no placeholder text left behind
- [ ] Every `checklist.md` item tiered `[critical]` / `[recommended]` / `[optional]`
- [ ] Frontmatter `name` matches the directory name
- [ ] Every control names a standard and, where applicable, a CWE
- [ ] `examples/README.md` has at least three vulnerable/fixed pairs, one of them a real-world shape
- [ ] Every vulnerable block labelled `Vulnerable:` and paired with a fix
- [ ] `prompts.md` covers all four tiers: beginner, developer, review, audit - plus anti-patterns
- [ ] `SKILL.md` has `When NOT to Use` and `Ownership Boundary` sections routing to the skill that does own it
- [ ] Catalog `ownership` states the owner boundary, protected assets, and every non-goal hand-off
- [ ] Framework and ecosystem coverage stated by name, with the gaps named too
- [ ] Reference files carry a version and the date verified
- [ ] Limitations section is specific, not boilerplate
- [ ] No real credentials, hostnames, or personal data anywhere
- [ ] Catalog relationships updated and `python scripts/validate_repository.py --write-skill-graph` run
- [ ] Row added to `skills/shared/references/standards-matrix.md`
- [ ] `AI_INSTRUCTIONS.md` registry and routing rows added
- [ ] Root `README.md` status table and skill count updated
- [ ] `CHANGELOG.md` entry added
