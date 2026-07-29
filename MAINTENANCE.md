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
skill identity, category, graph edges, standards cells, tool profile, routing hints, and ownership
metadata. The scaffold under `skills/shared/templates/` is **not** a production skill.

`ownership` identifies a skill's owner boundary, protected assets, and explicit non-goal hand-offs.
It is required for new skills and the current pilot skills; legacy skills receive warnings until
changed substantively. The human-readable `## Ownership Boundary` table mirrors owner IDs only.

`depends_on` must remain acyclic because it means “load this first.” Reciprocal `related`, `loads`,
or non-goal hand-offs can be valid for task-specific co-loading; treat them as a context-budget
review signal, not an automatic error.

After any skill add/rename/edge change:

1. Edit the catalog
2. Run `python scripts/validate_repository.py --write-skill-graph`
3. Run `python scripts/validate_repository.py`
4. Run `python scripts/validate_repository.py --write-frontmatter` if profiles changed
5. Update free-prose docs that the validator does not generate
6. Add a `CHANGELOG.md` entry under Unreleased

Use `python scripts/validate_repository.py --report-boundaries` to review the current ownership
and hand-off map without creating another generated document.

## Ownership touch policy

Ownership migration is incremental. A typo-only correction does not require a metadata sweep. A
substantive edit to a legacy skill - workflow, standards, routing, examples, limitations, or its
boundary - must add its catalog `ownership` object and `## Ownership Boundary` hand-off table in
the same change.

| Change | Required companion work |
|---|---|
| New or renamed skill | Complete tree, catalog ownership/edges, generated graph, standards matrix, AI routing, README counts, changelog, tests for validator behavior |
| Standards re-pin | Owning reference, central pins, catalog standards, matrix, changelog, owner review |
| Routing or graph edge | Catalog first, intentional reverse `related` edge, generated graph, AI routing if discovery changes |
| Validator or workflow behavior | Offline tests, CI workflow, scripts docs, maintenance/contributor guidance |
| Template/content policy | Scaffold, templates README, contributor guidance, owner review |
| Example-only correction | Local skill content and owner review; central updates only if scope, routing, or standards changed |

CODEOWNERS and branch protection provide review routing. Catalog ownership identifies the subject
boundary and hand-offs; it does not grant exclusive authority or replace independent review.

## Standards pins

## Standards pins

A re-verified standard moves in the same change:

1. Owning skill `references/<standard>.md` - version, URL, date checked
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
| External link sanity | weekly advisory monitor; review its deduplicated GitHub issue |

## Release sequence

1. Working tree clean on `main`
2. `CHANGELOG.md` has `## [X.Y.Z] - YYYY-MM-DD` (move from Unreleased)
3. `python scripts/validate_repository.py`
4. Secret scan (CI and/or local gitleaks)
5. Push or merge to `main`; `.github/workflows/release.yml` creates missing tag `vX.Y.Z` from the
   latest released changelog section and publishes the GitHub Release from that section
6. Manual fallback remains `./scripts/release.sh --version X.Y.Z --tag --push`
   or PowerShell `.\scripts\Release.ps1 -Version X.Y.Z -Tag -Push`

Never `git add -A`. Stage named paths only. Never force-push to clean a leak -
revoke first ([skills/core/secrets-management/references/exposure-response.md](skills/core/secrets-management/references/exposure-response.md)).

## Automation owned here

| Path | Role |
|---|---|
| `.github/workflows/validate.yml` | PR/main structure gate |
| `.github/workflows/secret-scan.yml` | Gitleaks |
| `.github/workflows/release.yml` | Validation, then automatic tag + GitHub Release from the latest released changelog section on `main` |
| `.github/workflows/external-link-check.yml` | Weekly advisory external-reference monitor and deduplicated issue lifecycle |
| `.github/CODEOWNERS` | Path review assignments; enforce with a GitHub ruleset/branch protection |
| `.github/dependabot.yml` | Actions and pip update PRs |
| `requirements.txt` | Python dependency surface for Dependabot; stdlib-only today |
| `.gitleaks.toml` | Scanner config + narrow didactic allowlist |

The external-link monitor is deliberately outside the release path. A 404/410 is a maintenance
signal; a 429, 5xx, timeout, or bot challenge is not proof that a pinned source disappeared.
Review the single `external-links` issue, correct stable failures, and close it only after a clean
run. CODEOWNERS requests review but does not enforce it unless the repository requires code-owner
review in its GitHub ruleset or branch protection.

## Deprecation

1. Add pointer at top of old `SKILL.md`
2. Keep directory name stable
3. Catalog status may become `Deprecated` in a later revision; until then document in CHANGELOG
4. Major bump only if paths/routing actually break
