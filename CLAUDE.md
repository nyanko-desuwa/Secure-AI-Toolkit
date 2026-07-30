# CLAUDE.md

Project rules live in [AGENTS.md](AGENTS.md) - read it first. This file adds the
Claude Code-specific commands and workflow.

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
python scripts/validate_repository.py --write-frontmatter     # align allowed-tools
python scripts/validate_repository.py --report-boundaries     # ownership + hand-offs

# Install skills into Claude Code dirs
./scripts/install-skills.sh --skills owasp,api-security --verify

# Release: push to main; .github/workflows/release.yml tags vX.Y.Z and publishes
```

## Workflow

- Run the verification trio before returning code, and report results honestly.
- Plain ASCII only: `=>` not the arrow glyph, straight quotes, `...` not the
  ellipsis glyph. Vietnamese diacritics in trigger keywords are the exception.
- `skill.yaml` files are generated - never hand-edit them. Change
  `catalog/skills.json` and regenerate.
- Honor the publish gate in `AI_INSTRUCTIONS.md` before any commit, push, or
  share. Stage named paths, never `git add -A`.
- Never commit `huong dan.md` or the `.authoring/` tracker (local-only,
  gitignored).
