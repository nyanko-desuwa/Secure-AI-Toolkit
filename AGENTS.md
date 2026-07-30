# AGENTS.md

Rules for any AI agent editing this repository. Vendor-neutral: Codex, Aider,
Amp, Cursor, and Claude Code (which also reads `CLAUDE.md`) all read this file.

To *use* the security skills inside another project, read
[AI_INSTRUCTIONS.md](AI_INSTRUCTIONS.md) instead. That is the consumer entry
point (skill registry, routing, output contract). This file is for *editing this
repository itself*.

## What this repo is

A static Markdown documentation pack of 47 security skills (26 core, 6 advanced,
5 enterprise, 10 architecture). There is no application runtime. The only code is
stdlib-only Python in `scripts/` for validation, install, and release
orchestration.

## Architecture: one boundary per skill

Every skill owns exactly one trust boundary or service boundary. Other skills may
reference it, but must not duplicate its policy, checklists, or review workflow.
This is the architecture of the whole repo, and it is what keeps the loading
budget in `AI_INSTRUCTIONS.md` from being blown by overlapping skills.

If a control already has an owner, extend that owner skill instead of creating a
new directory. This is what stops the catalog from sprouting `webhook-security`,
`graphql-security`, `redis-authentication`, or `jwt-security` when `api-security`,
`redis-security`, and `authentication` already own those boundaries.

## Creating a new skill

Do not create a new skill just because a topic is large. Size is not a boundary;
ownership is. Before adding a directory, the candidate must satisfy at least four
of these:

- Has its own protected assets that no existing skill guards.
- Owns a distinct trust or service boundary.
- Has a unique threat model and attack surface.
- Needs its own review workflow and checklist, not a section in another skill.
- Can be routed to independently by both the AI and a human.

If it does not clear four, extend the existing owner skill instead. This test is
the gate that keeps the one-boundary-per-skill architecture above intact; the
full bar a finished skill must meet is in `skills/shared/templates/README.md`.

Every skill - new or edited - must explicitly document:

- **Owner Boundary** - the single boundary it owns (catalog `ownership` +
  `## Ownership Boundary` table).
- **Related Skills** - adjacent boundaries it hands off to, not duplicates of.
- **Non-Goals** - what it deliberately does not cover, and which skill does.
- **Loads With** - the skills it expects to be co-loaded with.
- **Routing Triggers** - the request shapes and keywords that route to it (the
  `description:` triggers plus its rows in the `AI_INSTRUCTIONS.md` routing table).

## Source of truth

`catalog/skills.json` drives skill identity, category, graph edges, standards
cells, tool profile, ownership metadata, and context budget. Everything else is
derived from it:

- `skill.yaml` next to each `SKILL.md` is **generated** by
  `scripts/generate_skill_manifests.py`. Never hand-edit a `skill.yaml`.
- The graph tables and budget numbers are written back into the catalog by the
  validator (`--write-skill-graph`, `--write-budget`), not authored by hand.

`MAINTENANCE.md` covers version rules, the catalog, ownership, and the release
sequence. `skills/shared/templates/README.md` states the bar a new skill must
clear. Read both before a structural change.

## Editing rules

- **Plain ASCII / UTF-8-safe text only.** Use `=>` not the arrow glyph, straight
  quotes not smart quotes, `...` not the ellipsis glyph, `-` not en/em dash.
  Non-ASCII glyphs break `python scripts/validate_repository.py
  --extract-changelog` on a cp1252 terminal. Vietnamese diacritics in skill
  trigger keywords (for example inside a `description:` field) are the one
  intended exception.
- **Every control cites its standard**: OWASP Top 10 2025 category, ASVS 5.0
  chapter, and a CWE where one applies. An uncited control is an opinion.
- **Do not expand scope.** Fix the file you are in; note issues elsewhere rather
  than sweeping them up.
- **Verify version-specific claims** against the source with a check date. The
  Top 10 renumbers between editions.

## Verify before finishing (the trio)

Run all three from the repo root and report the results honestly:

```bash
python -m unittest discover -s tests -t . -v
python scripts/validate_repository.py
python scripts/generate_skill_manifests.py --check
```

If you edited any `SKILL.md` or `checklist.md`, character counts change, so also
rebudget and regenerate before the trio:

```bash
python scripts/validate_repository.py --write-budget
python scripts/generate_skill_manifests.py
```

## When you change a skill or the catalog

Condensed from the "When you change this repository" section of
`AI_INSTRUCTIONS.md` (link there rather than duplicating):

- New or modified skill => update its `README.md`, `checklist.md`, `examples/`.
- New skill => update `catalog/skills.json`, then the registry row and routing
  table in `AI_INSTRUCTIONS.md`, the `README.md` status table and count,
  `skills/shared/references/skill-graph.md` (with the reverse edge), and
  `skills/shared/references/standards-matrix.md`; run
  `python scripts/validate_repository.py --write-skill-graph`.
- Standard re-pinned => move the version and date together in the reference file,
  `AI_INSTRUCTIONS.md`, and `README.md`.
- Any change => add a `CHANGELOG.md` entry under `## [Unreleased]`.

`AGENTS.md` and `CLAUDE.md` are not skills. Do not add them to the catalog,
registry, or standards matrix.

## Never commit

- `huong dan.md` and the `.authoring/` tracker are local-only and gitignored.
  Never stage them, never quote them in a commit message, never cite them in a
  committed file.
- Stage named paths. Never `git add -A` or `git add .`.
- Never rewrite history or force-push to clean up a leak. Revoke at the provider
  first; see
  `skills/core/secrets-management/references/exposure-response.md`.

## Release

Land changes on `main` with a `CHANGELOG.md` section for the version. Pushing to
`main` triggers `.github/workflows/release.yml`, which validates, secret-scans,
creates the missing `vX.Y.Z` tag from the latest released changelog section, and
publishes the GitHub Release. It is idempotent: an existing tag is skipped. The
manual fallback is `scripts/release.sh` / `scripts/Release.ps1`.
