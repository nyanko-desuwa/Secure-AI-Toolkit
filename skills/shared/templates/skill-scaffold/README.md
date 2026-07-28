# <Skill Name> Skill

<One paragraph. What decisions does this skill make, and who is it for?>

## Purpose

<Why this skill exists as a separate thing rather than a section of another skill. Name the
standard it is grounded in — a skill that cites nothing is an opinion.>

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the workflow, and
pulls in the supporting file it needs at each step.

```text
SKILL.md                 entry point: workflow, severity rules
README.md                this file
checklist.md             pre-return verification
best-practices.md        patterns, with vulnerable/fixed pairs
common-mistakes.md       what goes wrong and why the fix works
troubleshooting.md       what to do when guidance conflicts
prompts.md               prompt examples per task type
references/
  <standard>.md          summary, version-pinned with a check date
examples/
  README.md              vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| <name> | <version> | <YYYY-MM-DD, against \<url\>> |

Do not fill this table from memory. Fetch the source, record the date. Category and
requirement IDs move between editions, and a stale ID is worse than no ID.

## Configuration

None. No build step, no dependency, no environment variable.

To use in Claude Code, keep this repository in the working directory or copy the skill
directory into `~/.claude/skills/`.

## Example Usage

```text
<A scoped prompt that produces findings rather than a category recital.>
```

More in [prompts.md](prompts.md).

## Limitations

Be specific. Boilerplate here is worse than nothing, because it reads as due diligence
without doing any.

- <What this skill structurally cannot catch, and what to pair it with>
- <Where the standard mapping is coarse>
- <What reading code cannot tell you about runtime>

## Security Notes

<If the skill contains deliberately vulnerable code, say so here and confirm every block is
labelled and paired with a fix.>

<Confirm there are no real credentials, hostnames, keys, or personal data.>

## References

- <Standard> — <url>
- <Standard> — <url>
