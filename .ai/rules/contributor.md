# Contributor Rules

Rules for any AI agent editing this repository. Full rules are in `AGENTS.md`.
This file is a portable Markdown summary — no tool-specific frontmatter.

## Before making any change

1. Read `AGENTS.md` and `AI_INSTRUCTIONS.md` for the authoritative rules.
2. Run the verification trio:
   ```
   python -m unittest discover -s tests -t . -v
   python scripts/validate_repository.py
   python scripts/generate_skill_manifests.py --check
   ```
3. If you edited any `SKILL.md` or `checklist.md`, rebudget first:
   ```
   python scripts/validate_repository.py --write-budget
   python scripts/generate_skill_manifests.py
   ```

## Architecture rules

- **One boundary per skill.** Do not duplicate policy, checklists, or review
  workflow across skills. If a control already has an owner, extend that skill.
- A new skill must satisfy at least 4 of 5: (1) distinct trust boundary,
  (2) different threat model, (3) no existing skill owns it, (4) full 11-file
  set is feasible, (5) real and common failure mode.
- `skill.yaml` files are **generated**. Change `catalog/skills.json` and run
  `python scripts/generate_skill_manifests.py`. Never hand-edit a `skill.yaml`.

## What to update when adding or changing a skill

- New skill => `catalog/skills.json` + registry row + routing row in
  `AI_INSTRUCTIONS.md` + `README.md` count + `skills/shared/references/skill-graph.md`
  (with the reverse edge) + `skills/shared/references/standards-matrix.md`
  + `CHANGELOG.md` under `## [Unreleased]`
- Any change => `CHANGELOG.md` entry under `## [Unreleased]`
- Standard re-pinned => update version and date in the reference file AND
  in `AI_INSTRUCTIONS.md` AND in `README.md` together

## Plain ASCII only

Use `=>` not the arrow glyph, straight quotes not smart quotes, `...` not the
ellipsis glyph, `-` not en/em dash. Vietnamese diacritics in skill trigger
keywords are the one exception.

## Never commit

- `huong dan.md`, `.authoring/`, temp files, scratch files.
- Use `git add -A` or `git add .` -- stage named paths only.
- Non-ASCII characters outside Vietnamese trigger keywords.
