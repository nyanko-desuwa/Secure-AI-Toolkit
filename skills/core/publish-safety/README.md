# Publish Safety Skill

What must be true before a private thing becomes a public thing. Covers the push, the visibility
flip, the package, the image, the deployed bundle, the store build, and the screenshot - and the
files that were never meant to leave the machine.

## Purpose

Publishing is a one-way door. Once a credential is public, no commit, force-push, unpublish, or
deleted repository takes it back; the only remediation is revocation at the provider. That makes
the publish boundary a distinct control point with its own failure modes, which is why it is a
skill rather than a section of another one.

The material either side of the door already has owners. `secrets-management` owns the credential
lifecycle - storage, delivery, rotation, and the revoke/rotate/investigate order.
`common-pitfalls` owns the build-output greps and the per-framework public env prefixes.
`devsecops` owns scanners as enforced pipeline gates. None of them owns the moment itself: the
gap between the files you edited and the files you are about to publish, and the fact that
`git status` describes the present tense while a public repository exposes the whole history.

Grounded in OWASP Top 10 2025 (A02, A03, A04), ASVS 5.0 (V13, V14), and CWE-527, CWE-540,
CWE-538, CWE-798, CWE-615, CWE-532 - each verified against its source, with the date recorded.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the six-step workflow
(inventory what ships → scan history → scan the built artifact → check the packaging manifest →
check the human channels → verify and report), and pulls in the supporting file it needs at each
step.

```text
SKILL.md                    one-way doors, workflow, severity, when NOT to use
README.md                   this file
checklist.md                pre-publish verification, grouped by surface
best-practices.md           patterns with vulnerable/fixed pairs
common-mistakes.md          what goes wrong and why the fix works
troubleshooting.md          when the guidance cannot be applied
prompts.md                  beginner, developer, review, and audit prompts
references/
  owasp-top10-2025.md       A02, A03, A04, A08 as they apply to publishing
  asvs-5.0.md               V13, V14, V15 chapter scope
  cwe-publishing.md         the six IDs that carry these findings
  platform-controls.md      GitHub, GitLab, npm, Docker behaviour
examples/
  README.md                 seven vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 - A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A08 Software or Data Integrity Failures | 2026-07-28, against `owasp.org/Top10/2025/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30) - V13 Configuration, V14 Data Protection, V15 Secure Coding and Architecture | 2026-07-28, against the ASVS project page |
| CWE | CWE-527, CWE-540, CWE-538, CWE-798, CWE-615, CWE-532 | 2026-07-28, each entry fetched from `cwe.mitre.org` |
| Platform behaviour | GitHub secret scanning and push protection, GitHub sensitive-data removal guidance, GitLab secret push protection, npm `files`/`.npmignore` precedence | 2026-07-28, against vendor documentation |

Version numbers and titles are pinned in `references/` with the date checked. Update the
reference file and this table together.

## Configuration

None. No build step, no dependency, no environment variable.

To use in Claude Code, keep this repository in the working directory so
`skills/core/publish-safety/SKILL.md` is readable, or copy the `publish-safety` directory into
`~/.claude/skills/`. The frontmatter `allowed-tools` is research-only (read, search, web lookup);
it cannot run `git push`, `npm publish`, or any other publishing command itself.

## Example Usage

Before the first push of a project:

```text
I am about to push this repo to GitHub for the first time and it will be public. Run
skills/core/publish-safety/checklist.md, sections "Before any push" and "Before flipping a
repository public". Show me the exact command output you based each answer on, and list
anything you could not verify.
```

Before publishing a package:

```text
Run npm pack --dry-run and list every file that will be in the tarball. Flag anything that is
not needed by a consumer of this package: env files, test fixtures, internal notes, build
scripts with hostnames in them. Then tell me the files field I should add to package.json.
```

After finding something already public:

```text
An AWS access key was pushed to this public repo two hours ago. Give me the ordered response
using skills/core/publish-safety/ and secrets-management/references/exposure-response.md. Be
explicit about what comes first and why rewriting history is not it.
```

More, including the anti-patterns worth avoiding, in [prompts.md](prompts.md).

## Limitations

- **Guidance, not a scanner.** No entropy analysis, no history walk, no pattern database. It
  tells you which commands to run and what to do with a hit. Pair it with `gitleaks` or
  `trufflehog` for the detection itself, and with provider-side push protection for prevention.
- **Cannot confirm a repository's actual visibility.** Reading files cannot tell you whether a
  repo is public, whether push protection is enabled, or whether a registry package is listed.
  Those need a check against the provider.
- **Cannot confirm revocation.** Only the provider's console or API can say a credential is dead.
  A skill that claims otherwise is guessing.
- **Cannot see what already left.** Forks, clones, mirrors, CDN caches, code-search indexes, CI
  logs, and notification emails are outside the repository. The skill says to assume they hold a
  copy, because that assumption is the only safe one - it cannot enumerate them.
- **Pattern matching misses unshaped secrets.** `AKIA...` and `sk_live_...` are recognisable; a
  bare 32-character database password is not. The reliable check is grepping for the literal
  value of each credential you own, which requires knowing the value.
- **Platform behaviour moves.** The npm precedence rules, GitHub bypass flow, and GitLab tier
  requirements were correct against vendor documentation on 2026-07-28. Re-check before relying
  on a specific default.
- **Ecosystem coverage is partial.** Git, npm, PyPI, Docker, and static hosting are covered in
  depth. Cargo, Go modules, Maven, NuGet, RubyGems, and Composer appear only by analogy; the
  allowlist-over-denylist reasoning transfers, the manifest field names do not.
- **This repository now runs its own publish-shaped gates.** Pull requests and tags run
  catalog/structure validation and Gitleaks (see `.github/workflows/` and `.gitleaks.toml`).
  That does not replace provider push protection or a consumer application's own CI - it only
  means the pack no longer documents a gate it refuses to run on itself.

## Security Notes

This skill contains deliberately unsafe configuration and commands in `best-practices.md`,
`common-mistakes.md`, and `examples/README.md`. Every such block is labelled `Vulnerable:` on its
first line and paired with a fixed version. Do not copy a labelled-vulnerable block into a
project.

The destructive commands in `troubleshooting.md` and `common-mistakes.md` - `git filter-repo`,
`git push --force`, `git rm --cached` - are shown because readers reach for them anyway, and the
point being made is usually that they are not the fix. Read the surrounding paragraph before
running one.

Every credential, key, hostname, account ID, and URL in this skill is an obvious placeholder.
Nothing here is a live value and nothing is formatted to look live without saying so.
Key-shaped strings carry `PLACEHOLDER` or `EXAMPLE`.

If you paste a real credential into a prompt while using this skill, treat it as exposed and run
[secrets-management/references/exposure-response.md](../secrets-management/references/exposure-response.md).
Model providers log requests.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Secrets Management Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- CWE-527 Exposure of Version-Control Repository to an Unauthorized Control Sphere - <https://cwe.mitre.org/data/definitions/527.html>
- CWE-540 Inclusion of Sensitive Information in Source Code - <https://cwe.mitre.org/data/definitions/540.html>
- GitHub, removing sensitive data from a repository - <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository>
- npm `files` field and `.npmignore` - <https://docs.npmjs.com/cli/v11/configuring-npm/package-json#files>
