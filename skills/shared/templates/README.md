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

`skills/core/owasp/` is the worked example. Read it before starting — it is easier to match
than to describe.

## The bar

A skill is not done because the files exist. It is done when:

- Every control cites a standard. Top 10 category, ASVS chapter, and CWE where one applies.
  A control with no citation is an opinion, and opinions do not survive review.
- Every pattern shows both states. Vulnerable code, fixed code, and a sentence on why the
  fix closes the hole rather than just looking safer.
- Limitations are stated. If a control has a known gap, name it. The SSRF example in
  `core/owasp/examples/README.md` says outright that it is still open to DNS rebinding —
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

## Frontmatter

`SKILL.md` needs YAML frontmatter for Claude Code. Other assistants ignore it.

```yaml
---
name: skill-name
description: 'One line on when to use this. Triggers: "keyword", "keyword", "từ khoá".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---
```

Keep `allowed-tools` tight. These skills read and advise; none of them need to run arbitrary
commands. Include Vietnamese trigger words alongside English ones.

## Checklist for a new skill

- [ ] All eleven files present, no placeholder text left behind
- [ ] Frontmatter `name` matches the directory name
- [ ] Every control names a standard and, where applicable, a CWE
- [ ] Every vulnerable block labelled `Vulnerable:` and paired with a fix
- [ ] Reference files carry a version and the date verified
- [ ] Limitations section is specific, not boilerplate
- [ ] No real credentials, hostnames, or personal data anywhere
- [ ] Root `README.md` status table updated
- [ ] `CHANGELOG.md` entry added
