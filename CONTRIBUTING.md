# Contributing

## Before you start

- Read [`AI_INSTRUCTIONS.md`](AI_INSTRUCTIONS.md) for routing and the output contract
- Read [`skills/shared/templates/README.md`](skills/shared/templates/README.md) for the finished-skill bar
- Read [`MAINTENANCE.md`](MAINTENANCE.md) for versioning and catalog rules
- Run `python scripts/validate_repository.py` and `python -m unittest discover -s tests -t . -v`
  on a clean tree so you know the baseline
- Use [threat-model](docs/templates/threat-model.md) and [security-design-review](docs/templates/security-design-review.md) templates for a material boundary change

## Adding or changing a skill

1. Copy the scaffold only for **new** skills:

   ```bash
   cp -r skills/shared/templates/skill-scaffold skills/core/my-skill
   ```

2. Fill every required file. New skills need the content policy in the templates README:
   seven example pairs, four prompt tiers, `When NOT to Use`, named framework coverage,
   pinned references, no placeholder text.

3. Prove the new skill should exist before copying the scaffold. It must have all three:
   - a specific owner/trust/service boundary;
   - a routing path that lets an assistant select it; and
   - explicit non-goals with a hand-off to the existing owner.

   It must also have at least three of five distinguishing signals: protected assets, attack
   surface/threat model, a verifiable workflow, primary standards, or an operational lifecycle.
   If it does not clear that bar, extend the existing owner skill instead.

4. Add a row to [`catalog/skills.json`](catalog/skills.json) with:
   - `name` matching the directory and `category` / `path`
   - `depends_on` / `related` / `loads` (canonical directory names only - no `owasp-security` aliases)
   - `standards`, `allowed_tools_profile` (almost always `research-only`), and `routing_hints`
   - `ownership`: `owner_boundary`, protected assets, and non-goals with canonical owner IDs

5. Update the standards matrix and registry/routing/count prose where applicable, then regenerate
   the catalog-derived graph:

   ```bash
   python scripts/validate_repository.py --write-skill-graph
   ```

6. Apply tool profile:

   ```bash
   python scripts/validate_repository.py --write-frontmatter
   python scripts/validate_repository.py
   ```

7. Add `CHANGELOG.md` under Unreleased.

8. Stage **named paths** only. Never `git add -A`.

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

- structure/catalog/frontmatter/ownership/graph/internal-link validation
- gitleaks

External links are checked by a separate scheduled/advisory workflow. They do not
block PR merge or release. PRs should keep the tree green on the blocking checks.
If a didactic example trips gitleaks, prefer making the literal obviously fake;
only then add a minimal allowlist entry in `.gitleaks.toml` with rationale.

## Code of conduct for security content

- Every control cites a standard where possible
- Every vulnerable example is labelled and paired with a fix
- No real secrets, hostnames of real victims, or personal data
- State limitations honestly - especially what code review cannot prove
