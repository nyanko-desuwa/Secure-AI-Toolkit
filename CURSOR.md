# CURSOR.md

Project rules live in [AGENTS.md](AGENTS.md) - read it first. This file adds the
Cursor-specific commands and workflow.

To *use* the security skills in another project, read
[AI_INSTRUCTIONS.md](AI_INSTRUCTIONS.md). This file is for *editing this repo*.

## Commands

```bash
# Verify (run all three before returning any change)
python -m unittest discover -s tests -t . -v
python scripts/validate_repository.py
python scripts/generate_skill_manifests.py --check

# Regenerate after editing SKILL.md / checklist.md (character counts drive budget)
python scripts/validate_repository.py --write-budget
python scripts/generate_skill_manifests.py

# Other maintenance
python scripts/validate_repository.py --write-skill-graph    # regenerate graph tables
python scripts/validate_repository.py --write-frontmatter    # align allowed-tools
python scripts/validate_repository.py --report-boundaries    # ownership + hand-offs
```

## Cursor-specific rules

- `.cursor/rules/cursor-security-routing.mdc` - skill routing for code files.
- `.cursor/rules/cursor-contributor.mdc` - contributor rules for repo edits.
- Cursor's Composer will load the relevant rule automatically based on the glob patterns.

## Workflow

- Plain ASCII only: `=>` not the arrow glyph, straight quotes, `...` not the ellipsis glyph.
  Vietnamese diacritics in trigger keywords are the exception.
- `skill.yaml` files are generated - never hand-edit them. Change `catalog/skills.json` and regenerate.
- Honor the publish gate in `AI_INSTRUCTIONS.md` before any commit, push, or share.
  Stage named paths, never `git add -A`.
- Never commit local-only notes or the `.authoring/` scratch directory (gitignored).
