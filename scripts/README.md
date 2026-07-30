# Scripts

Operational helpers for this documentation pack. No application runtime - only
validation, install, and release orchestration.

| Script | Purpose |
|---|---|
| `validate_repository.py` | Canonical validator (catalog, ownership, generated graph, skill manifests, skill shape, frontmatter, internal links, changelog extract) |
| `generate_skill_manifests.py` | Projects `catalog/skills.json` into a `skill.yaml` next to each `SKILL.md`; `--check` fails on drift |
| `check_external_links.py` | Advisory external Markdown-link monitor for scheduled CI; never a release gate |
| `render_link_issue.py` | Renders the advisory external-link issue body and state files for CI |
| `validate-repository.sh` / `Validate-Repository.ps1` | Launchers |
| `install-skills.sh` / `Install-Skills.ps1` | Install production skills into Claude Code dirs |
| `release.sh` / `Release.ps1` | Maintainer release guard (validate → scan → optional tag/push) |

## Validate

```bash
python scripts/validate_repository.py
python scripts/validate_repository.py --write-frontmatter   # align allowed-tools
python scripts/validate_repository.py --write-skill-graph   # regenerate catalog-derived graph tables
python scripts/generate_skill_manifests.py                  # regenerate every skill.yaml from the catalog
python scripts/generate_skill_manifests.py --check          # fail if any skill.yaml drifted
python scripts/validate_repository.py --report-boundaries   # print ownership and hand-offs
python scripts/validate_repository.py --extract-changelog 1.0.1
python -m unittest discover -s tests -t . -v

# Advisory external-reference report; it always exits zero for link reachability.
python scripts/check_external_links.py --output external-link-report.json
python scripts/render_link_issue.py --report external-link-report.json --run-url "$RUN_URL"
```

PowerShell:

```powershell
.\scripts\Validate-Repository.ps1
```

## Install skills

Bash (user scope, selected skills):

```bash
./scripts/install-skills.sh --skills owasp,api-security,publish-safety --verify
```

PowerShell:

```powershell
.\scripts\Install-Skills.ps1 -Skills owasp,api-security,publish-safety -Verify
.\scripts\Install-Skills.ps1 -All -Mode copy
# Symlinks on Windows may need Developer Mode or elevation:
.\scripts\Install-Skills.ps1 -Skills owasp -Mode symlink
```

Rules:

- Only catalog production skills are installable
- `skills/shared` and the scaffold are never installed
- Existing destinations fail closed unless `--force` / `-Force`
- Prefer a small selection over `--all` (startup context cost)

## Release

Preferred path:

1. Land changes on `main` with a `CHANGELOG.md` section for the version
2. Push or merge to `main`
3. GitHub Actions `.github/workflows/release.yml` validates, secret-scans, creates the missing
   `vX.Y.Z` tag from the latest released changelog section, and creates the GitHub Release

Manual fallback:

```bash
./scripts/release.sh --version X.Y.Z --tag --push
```

Local-only tag without push:

```bash
./scripts/release.sh --version 1.1.0 --tag
```

PowerShell:

```powershell
.\scripts\Release.ps1 -Version 1.1.0 -Tag -Push
```

The helper never runs `git add -A`, never force-pushes, and never rewrites history.
