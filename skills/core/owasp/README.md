# OWASP Security Skill

Reference implementation for this repository. Other skills follow its file layout.

## Purpose

Give an AI assistant a way to make security decisions that trace back to a published
standard, instead of reciting generic advice. Every control in this skill names the OWASP
Top 10 category and ASVS chapter it serves, so a finding can be defended and a reviewer can
check it.

## How It Works

The skill is plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the
five-step workflow (scope, map, apply, verify, report), and pulls in the supporting file it
needs at each step.

```text
SKILL.md                   workflow and severity rules, entry point
README.md                  this file
checklist.md               pre-return verification, grouped by category
best-practices.md          patterns, with vulnerable/fixed pairs
common-mistakes.md         what goes wrong and why the fix works
troubleshooting.md         what to do when guidance conflicts
prompts.md                 prompt examples per task type
references/
  owasp-top10-2025.md      category list, questions each implies
  api-top10-2023.md        API-specific categories
  asvs-5.0.md              chapter map, verification levels
examples/
  README.md                seven vulnerable/fixed pairs, one per category
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 | 2026-07-28, against `owasp.org/Top10/2025/` |
| OWASP API Security Top 10 | 2023 | 2026-07-28, against `owasp.org/API-Security/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28, against the ASVS project page |

Version numbers are pinned in `references/` with the date they were checked. When OWASP
publishes a new edition, update the reference file and the table above together.

## Configuration

None. There is no build step, no dependency, and no environment variable.

To use the skill in Claude Code, either keep this repository in the working directory so
`skills/core/owasp/SKILL.md` is readable, or copy the `owasp` directory into
`~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read, search, and web
lookup plus `ls`/`cat`; it cannot run arbitrary commands.

## Example Usage

Ask for a review scoped to a standard:

```text
Review src/api/invoices.py against OWASP Top 10 2025. Report category, location,
exploitation path, and fix for each finding. Skip anything without an exploitation path.
```

Ask for the checklist before accepting generated code:

```text
Run skills/core/owasp/checklist.md against the diff. For each unchecked box, either fix it
or state why it does not apply.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not a scanner. It has no dataflow analysis and will miss vulnerabilities
  that need cross-file taint tracking. Pair it with SAST.
- Examples are in Python, JavaScript/TypeScript, Java, and PHP. The patterns generalise;
  the syntax does not. Nothing here is Go, Rust, C#, or Ruby specific.
- ASVS mapping is at chapter level (V1 to V17), not individual requirement IDs. For formal
  ASVS verification, work from the official CSV.
- Says nothing about whether a control is correctly deployed. Reading code cannot confirm
  runtime configuration.
- No compliance mapping. ISO 27001, SOC 2, and PCI DSS are planned for the `compliance`
  skill and are not covered here.

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired
with a fixed version. Do not copy a labelled-vulnerable block into a project.

The examples use placeholder values only. There are no real credentials, hostnames, or
personal data in this skill.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Cheat Sheet Series - <https://cheatsheetseries.owasp.org/>
- CWE Top 25 - <https://cwe.mitre.org/top25/>
