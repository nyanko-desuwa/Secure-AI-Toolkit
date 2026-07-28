# Scripts

Operational helpers for this documentation pack. No application runtime — only
validation, install, and release orchestration.

| Script | Purpose |
|---|---|
| `validate_repository.py` | Canonical validator (catalog, skill shape, frontmatter, links, changelog extract) |
| `validate-repository.sh` / `Validate-Repository.ps1` | Launchers |
| `install-skills.sh` / `Install-Skills.ps1` | Install production skills into Claude Code dirs |
| `release.sh` / `Release.ps1` | Maintainer release guard (validate → scan → optional tag/push) |

## Validate

```bash
python scripts/validate_repository.py
python scripts/validate_repository.py --write-frontmatter   # align allowed-tools
python scripts/validate_repository.py --extract-changelog 1.0.1
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
2. `./scripts/release.sh --version X.Y.Z --tag --push`
3. GitHub Actions `.github/workflows/release.yml` validates, secret-scans, and
   creates the GitHub Release from the changelog section

Local-only tag without push:

```bash
./scripts/release.sh --version 1.1.0 --tag
```

PowerShell:

```powershell
.\scripts\Release.ps1 -Version 1.1.0 -Tag -Push
```

The helper never runs `git add -A`, never force-pushes, and never rewrites history.
