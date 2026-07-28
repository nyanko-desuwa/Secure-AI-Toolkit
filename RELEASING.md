# Releasing

How a version of this repository gets cut. Short, because there is no build: the artifact is the
Markdown, and the release is a tag plus release notes that already exist in `CHANGELOG.md`.

## Version rules

This is a documentation pack consumed by other people's projects. Their assistants load
`AI_INSTRUCTIONS.md` and route themselves from there, so "breaking" means *routing* breaks, not
that an API changed.

| Bump | For |
|---|---|
| Patch | A content fix, a re-worded section, or one new skill that nothing else has to change to accommodate |
| Minor | A new category directory, a standards re-pin, or a new central rule in `AI_INSTRUCTIONS.md` |
| Major | A change that breaks how an assistant routes: a skill directory renamed or deleted, the registry restructured, the read order changed |

Deleting a skill directory is a major bump on its own. Every prompt that names its path stops
working, and there is no deprecation warning in a Markdown file — see the deprecation rule in
[skills/shared/templates/README.md](skills/shared/templates/README.md): leave the directory in
place with a pointer at the top of `SKILL.md`.

## Before tagging

Run the repository's own gate. It is the same one the pack tells its readers to run, so skipping
it here would be the clearest possible inconsistency.

```bash
# 1. What is actually about to be published
git status --porcelain
git diff --stat --cached

# 2. History, not just the worktree — this repository is public
git log --all --full-history --oneline -- ".env" ".env.*" "*.pem" "*.key" "*credentials*"

# 3. No credential-shaped literal introduced by the change
git diff --cached | grep -nE "AKIA[0-9A-Z]{16}|sk_live_|ghp_|-----BEGIN [A-Z ]*PRIVATE KEY"

# 4. Local-only files are absent from the staged set
git diff --cached --name-only
```

Stage named paths. Never `git add -A` or `git add .` — this repository has gitignored local-only
files in its root, and blanket staging is exactly how one becomes tracked.

Then the content checks, which are the only verification this repository has:

```bash
# Skill count matches every place it is written down
find skills -name SKILL.md | wc -l          # includes the scaffold; subtract 1

# No scaffold text survived
grep -rn "TODO\|FIXME\|<skill-name>\|Lorem" skills/ --include="*.md"

# Every vulnerable block has a fix in the same file
grep -rc "Vulnerable:" skills/ --include="*.md"
```

A skill count that disagrees between `AI_INSTRUCTIONS.md`, the root `README.md`, and the
filesystem is the most common defect here, because three files have to move together.

## Standards pins move in three places together

A re-verified standard is not one edit. Update all of these in the same commit:

1. The owning skill's `references/<standard>.md` — version, source URL, and the date checked
2. The `## Pinned versions` table in [AI_INSTRUCTIONS.md](AI_INSTRUCTIONS.md)
3. The `## Standards` table in [README.md](README.md)

Plus [skills/shared/references/README.md](skills/shared/references/README.md) if it is a primary
standard, and [skills/shared/references/standards-matrix.md](skills/shared/references/standards-matrix.md)
if the category IDs themselves changed.

A pin that is current in one file and stale in another is worse than a uniformly stale pin: a
reader who checks one place and finds today's date stops checking.

## Tag and release

Release tags sit on `main`. Noting it because the usual habit is to branch first, and that is
wrong for a tag.

```bash
# Notes come from CHANGELOG.md. Do not write new ones.
git tag -a v1.0.1 -m "1.0.1"
git push origin main
git push origin v1.0.1
```

Then create the release, with the matching `CHANGELOG.md` section as the body:

```bash
gh release create v1.0.1 --title "v1.0.1" --notes-file <(sed -n '/## \[1.0.1\]/,/## \[1.0.0\]/p' CHANGELOG.md)
```

Without `gh` installed, open
`https://github.com/nyanko-desuwa/Secure-AI-Toolkit/releases/new?tag=v1.0.1` and paste the same
section.

## What is deliberately not here

No CI, no pre-commit hooks, no `.gitleaks.toml`. This repository holds no credentials of its own,
and adding scanning configuration to a content repository would be config for its own sake. The
consequence is that the checks above are manual, and
[skills/core/publish-safety/README.md](skills/core/publish-safety/README.md) states that
inconsistency in its limitations rather than leaving a reader to spot it.

If this repository ever holds a credential — a publishing token, a docs deploy key — that decision
reverses, and the configs to copy are in
[skills/core/devsecops/examples/pre-commit-config.yaml](skills/core/devsecops/examples/pre-commit-config.yaml).
