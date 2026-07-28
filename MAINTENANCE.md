# Maintenance

How this documentation pack stays coherent. Day-to-day contribution steps live in
[CONTRIBUTING.md](CONTRIBUTING.md). Install/release commands live in
[scripts/README.md](scripts/README.md).

## Version rules

The artifact is Markdown consumed by other people's assistants. "Breaking" means
**routing** breaks, not that an API changed.

| Bump | For |
|---|---|
| **Patch** | Content fix, re-worded section, or one new skill that nothing else must change to accommodate |
| **Minor** | New category directory, standards re-pin, new central rule in `AI_INSTRUCTIONS.md`, or new automation that changes maintainer workflow |
| **Major** | Skill directory renamed or deleted, registry/read-order restructured, or assistant routing broken |

Deleting a skill directory is a major bump. Prefer deprecation: leave the
directory, put a replacement pointer at the top of `SKILL.md`, and note it in
`CHANGELOG.md`.

## Canonical catalog

[`catalog/skills.json`](catalog/skills.json) is the source of truth for production
skill identity, category, graph edges, standards cells, tool profile, and routing
hints. The scaffold under `skills/shared/templates/` is **not** a production skill.

After any skill add/rename/edge change:

1. Edit the catalog (or regenerate edges carefully)
2. Run `python scripts/validate_repository.py`
3. Run `python scripts/validate_repository.py --write-frontmatter` if profiles changed
4. Update free-prose docs that the validator does not generate
5. Add a `CHANGELOG.md` entry under Unreleased

## Standards pins

A re-verified standard moves in the same change:

1. Owning skill `references/<standard>.md` — version, URL, date checked
2. `## Pinned versions` in [`AI_INSTRUCTIONS.md`](AI_INSTRUCTIONS.md)
3. `## Standards` in [`README.md`](README.md)
4. [`skills/shared/references/README.md`](skills/shared/references/README.md) when it is a primary standard
5. [`skills/shared/references/standards-matrix.md`](skills/shared/references/standards-matrix.md) and the catalog `standards` fields when category IDs change

Cadence:

| Work | Cadence |
|---|---|
| Primary OWASP / ASVS pin spot-check | at least quarterly |
| Full standards re-verify | at least annually, and after major upstream releases |
| GitHub Actions SHA refresh | when Dependabot opens PRs; review diffs |
| Gitleaks allowlist review | whenever an entry is added; re-read quarterly |
| External link sanity | quarterly (manual or future checker) |

## Release sequence

1. Working tree clean on `main`
2. `CHANGELOG.md` has `## [X.Y.Z] - YYYY-MM-DD` (move from Unreleased)
3. `python scripts/validate_repository.py`
4. Secret scan (CI and/or local gitleaks)
5. `./scripts/release.sh --version X.Y.Z --tag --push`
   or PowerShell `.\scripts\Release.ps1 -Version X.Y.Z -Tag -Push`
6. Tag workflow `.github/workflows/release.yml` creates the GitHub Release from the changelog section

Never `git add -A`. Stage named paths only. Never force-push to clean a leak —
revoke first ([skills/core/secrets-management/references/exposure-response.md](skills/core/secrets-management/references/exposure-response.md)).

## Automation owned here

| Path | Role |
|---|---|
| `.github/workflows/validate.yml` | PR/main structure gate |
| `.github/workflows/secret-scan.yml` | Gitleaks |
| `.github/workflows/release.yml` | Tag validation + GitHub Release |
| `.github/dependabot.yml` | Actions update PRs |
| `.gitleaks.toml` | Scanner config + narrow didactic allowlist |

## Deprecation

1. Add pointer at top of old `SKILL.md`
2. Keep directory name stable
3. Catalog status may become `Deprecated` in a later revision; until then document in CHANGELOG
4. Major bump only if paths/routing actually break
