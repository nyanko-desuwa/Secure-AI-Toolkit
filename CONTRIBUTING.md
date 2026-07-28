# Contributing

## Before you start

- Read [`AI_INSTRUCTIONS.md`](AI_INSTRUCTIONS.md) for routing and the output contract
- Read [`skills/shared/templates/README.md`](skills/shared/templates/README.md) for the finished-skill bar
- Read [`MAINTENANCE.md`](MAINTENANCE.md) for versioning and catalog rules
- Run `python scripts/validate_repository.py` on a clean tree so you know the baseline

## Adding or changing a skill

1. Copy the scaffold only for **new** skills:

   ```bash
   cp -r skills/shared/templates/skill-scaffold skills/core/my-skill
   ```

2. Fill every required file. New skills need the content policy in the templates README:
   seven example pairs, four prompt tiers, `When NOT to Use`, named framework coverage,
   pinned references, no placeholder text.

3. Add a row to [`catalog/skills.json`](catalog/skills.json) with:
   - `name` matching the directory
   - `category` / `path`
   - `depends_on` / `related` / `loads` (canonical directory names only — no `owasp-security` aliases)
   - `standards` cells
   - `allowed_tools_profile` (almost always `research-only`)
   - `routing_hints` for code-surface matching

4. Mirror graph edges in free-prose docs if you edit them by hand:
   [`skills/shared/references/skill-graph.md`](skills/shared/references/skill-graph.md),
   [`skills/shared/references/standards-matrix.md`](skills/shared/references/standards-matrix.md),
   registry/routing in `AI_INSTRUCTIONS.md`, counts/layout in `README.md`.

5. Apply tool profile:

   ```bash
   python scripts/validate_repository.py --write-frontmatter
   python scripts/validate_repository.py
   ```

6. Add `CHANGELOG.md` under Unreleased.

7. Stage **named paths** only. Never `git add -A`.

## Permissions

Production skills default to:

```yaml
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
```

Do not grant `Write` or `Edit` in skill frontmatter. Publish-boundary writes to a
**consumer** project (ignore files, `.env.example`) are governed by the gate in
`AI_INSTRUCTIONS.md`, not by skill tool grants.

## Pull requests

CI runs:

- structure/catalog/frontmatter/link validation
- gitleaks

PRs should keep the tree green on both. If a didactic example trips gitleaks,
prefer making the literal obviously fake; only then add a minimal allowlist entry
in `.gitleaks.toml` with rationale.

## Code of conduct for security content

- Every control cites a standard where possible
- Every vulnerable example is labelled and paired with a fix
- No real secrets, hostnames of real victims, or personal data
- State limitations honestly — especially what code review cannot prove
