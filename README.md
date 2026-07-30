# Secure AI Toolkit

Security skills for AI coding assistants. Plain Markdown, no runtime, no dependencies, no
install step.

An assistant that writes code will make security decisions whether or not you asked it to.
Left alone it produces plausible-looking advice: sanitize your inputs, use HTTPS, don't store
passwords in plaintext. True, generic, and untraceable. Nobody can review it, because there
is nothing to review it against.

This repository is the other approach. Every control here names the OWASP Top 10 category and
ASVS chapter it serves, plus a CWE where one applies. That makes a finding defensible, a fix
checkable, and a disagreement resolvable by reading the standard rather than by arguing about
instinct.

> **Using this with an AI assistant?** Point it at
> [AI_INSTRUCTIONS.md](AI_INSTRUCTIONS.md) - that is the machine-facing entry point, with the
> skill registry, routing rules, and output contract. This README is the human introduction.

## Why this exists

Three problems, all of them observable in AI-generated code today.

**Generic advice does not survive review.** "Validate user input" tells a developer nothing
about whether the fix belongs at the boundary or at the sink, whether an allowlist or a regex
is appropriate, or what the endpoint still leaks afterwards. A control tied to
`A05:2025 · ASVS V2 · CWE-89` can be argued about precisely.

**Recalled category IDs are wrong more often than they look.** The OWASP Top 10 renumbers
between editions. An assistant confidently citing "A03 Injection" is working from the 2021
list; in 2025 A03 is Software Supply Chain Failures and Injection is A05. Every version claim
in this repository carries the source URL and the date it was checked, so staleness is visible
instead of invisible.

**Overselling a security tool is itself a risk.** A checklist that returns all green teaches
people to ignore checklists. The skills here state their gaps: the SSRF example says outright
that its own fix remains open to DNS rebinding, and the file upload example names polyglot
files as a limit of magic-number detection. That honesty is the design, not an oversight.

## What is inside

Skills are directories of Markdown. Nothing executes, nothing is fetched at runtime, nothing
needs building. An assistant reads `SKILL.md`, follows its workflow, and pulls in supporting
files as needed.

Each skill follows the same shape:

```text
skills/core/owasp/
├── SKILL.md              entry point: frontmatter, workflow, severity rules
├── README.md             purpose, configuration, limitations, security notes
├── checklist.md          pre-return verification, grouped by Top 10 category
├── best-practices.md     patterns, each with a vulnerable/fixed pair
├── common-mistakes.md    what goes wrong, and why the fix works
├── troubleshooting.md    what to do when the guidance conflicts
├── prompts.md            prompts that produce findings instead of recitals
├── references/           standard summaries, version-pinned with a check date
└── examples/             vulnerable and fixed code side by side
```

The workflow inside `SKILL.md` is five steps - scope, map, apply, verify, report - and the
verify step is the one that matters most in practice. It is what turns "here is some code"
into "here is some code, and here is what I checked and what I could not."

## Status

All 47 skills are written end to end. Every skill includes its workflow, checklist, real
vulnerable/fixed code, limitations, and version-pinned references.

| Area | State |
|---|---|
| `core/*` (26) | Complete |
| `advanced/*` (6) | Complete |
| `enterprise/*` (5) | Complete |
| `architecture/*` (10) | Complete |
| `shared/checklists`, `shared/prompts`, `shared/references` | Ready |
| `shared/templates` | Skill scaffold, ready to copy |

A directory is not marked complete because `SKILL.md` exists. It is complete only after its
checklist, examples, references, placeholder scan, frontmatter, and limitations have been
verified. Half-written security guidance is worse than none: it looks authoritative and covers
less than it appears to.

## Quick start

Nothing to build and nothing to install. Clone it and point your assistant at
`AI_INSTRUCTIONS.md`:

```bash
git clone https://github.com/nyanko-desuwa/Secure-AI-Toolkit.git
```

Keep the repository in your project, or beside it, and the assistant reads
`skills/core/owasp/SKILL.md` in place. That is the whole setup for most tools.

To get `/owasp`-style invocation and automatic routing in Claude Code, install the skills
properly - see below.

## Installing as Claude Code skills

Claude Code discovers a skill as a directory containing `SKILL.md`, one level under a
`skills` directory. It does not recurse into category folders, so the four categories in this
repository have to be flattened on the way in. The directory name becomes the command you
type.

| Scope | Path | Applies to |
|---|---|---|
| Personal | `~/.claude/skills/<name>/SKILL.md` | every project on your machine |
| Project | `.claude/skills/<name>/SKILL.md` | that repository, and anyone who clones it |

Verified against the Claude Code skills documentation on 2026-07-28:
<https://code.claude.com/docs/en/skills>

### Install a few skills

Recommended. Pick what the project actually needs.

```bash
mkdir -p ~/.claude/skills
cp -r Secure-AI-Toolkit/skills/core/owasp           ~/.claude/skills/owasp
cp -r Secure-AI-Toolkit/skills/core/common-pitfalls ~/.claude/skills/common-pitfalls
cp -r Secure-AI-Toolkit/skills/core/publish-safety  ~/.claude/skills/publish-safety
```

Then `/owasp`, `/common-pitfalls`, `/publish-safety`. Each skill's `description` frontmatter
also lets Claude load it on its own when the work matches - writing a query, adding an upload
endpoint, pushing a branch.

### Install all 47

```bash
mkdir -p ~/.claude/skills
for d in Secure-AI-Toolkit/skills/{core,advanced,enterprise,architecture}/*/; do
  cp -r "$d" ~/.claude/skills/
done
```

`skills/shared/` is excluded deliberately: it holds cross-cutting checklists, prompts, and
references, not skills, and its only `SKILL.md` is the authoring scaffold.

Directory names are unique across all four categories, so flattening needs no renaming. Check
for collisions with skills you already have - same name means the personal copy wins over a
project one, and any of them override a bundled skill of that name.

### Symlink instead of copy

Keeps one checkout as the source of truth, so `git pull` updates every installed skill:

```bash
ln -s "$PWD/Secure-AI-Toolkit/skills/core/owasp" ~/.claude/skills/owasp
```

Claude Code follows the symlink and reads `SKILL.md` from the target. This also preserves the
handful of cross-skill relative links - `publish-safety/SKILL.md` points at
`../common-pitfalls/references/secret-exposure.md`, which resolves inside the checkout but
dangles after a flat copy of only one of the two.

### Per-project, committed

```bash
mkdir -p .claude/skills
cp -r ../Secure-AI-Toolkit/skills/core/api-security .claude/skills/api-security
git add .claude/skills/api-security
```

Committing the skill is how teammates and cloud sessions get it. Personal skills under
`~/.claude/skills/` are local to your machine and are not read by Cowork or cloud sessions.
A project skill's `allowed-tools` only takes effect after you accept the workspace trust
dialog, which is the point at which you should have read what you are trusting.

### Confirm it worked

Run `/skills` in Claude Code and look for the names you installed. Adding or editing a skill
inside an existing `skills` directory is picked up mid-session; creating the top-level
`~/.claude/skills/` or `.claude/skills/` directory for the first time needs a restart before
it is watched.

### Worth knowing before you install all of them

- **Every installed skill costs context at startup.** Only the description is loaded until a
  skill is used, but 47 descriptions is roughly 17 KB of every session. Installing the three
  or four that match the project beats installing the set.
- **The frontmatter is Claude Code specific and inert elsewhere.** `allowed-tools` is deliberately
  narrow: read, search, and web lookup only. Nothing here needs write access or arbitrary shell
  access to do its job.
- **This is guidance, not a scanner.** Installing 47 skills does not add a security gate. See
  [Limitations](#limitations).

### Other assistants

Cursor, Copilot, Codex CLI, Gemini CLI, Continue, Cline, Roo Code, and Kiro read Markdown from
their own rules or context directories. Point the tool at `AI_INSTRUCTIONS.md` and copy or
reference the skill directories from wherever it loads context. The Markdown works anywhere;
only the YAML frontmatter is Claude Code specific, and it is ignored elsewhere.

## Using it

Scope the request and name the standard. Vague prompts produce category recitals; specific
prompts produce findings.

```text
Review src/api/invoices.py against OWASP Top 10 2025. For each finding give the category,
file:line, why it is exploitable, and the fix. Skip anything without an exploitation path.
```

That last sentence is the useful part. Asking for an exploitation path is what separates a
vulnerability from a code smell, and it stops the assistant padding the list.

Before accepting generated code:

```text
Run skills/core/owasp/checklist.md against the diff. Mark each item pass, fail, or not
applicable with a reason. Do not mark anything pass that you have not actually checked.
```

Design review is cheaper than code review:

```text
I am adding an endpoint that lets users export their own data as a CSV. Before I write it,
what controls does it need? Map each to a Top 10 category and an ASVS requirement.
```

More, including the anti-patterns worth avoiding, in
[skills/core/owasp/prompts.md](skills/core/owasp/prompts.md).

## Layout

```text
.
├── AI_INSTRUCTIONS.md    entry point for AI assistants: registry, rules, output contract
├── README.md             this file
├── CHANGELOG.md
├── LICENSE
└── skills/
    ├── core/             common-pitfalls · owasp · secure-code-review · api-security
    │                     mvc-security · authentication · database-security
    │                     secrets-management · file-upload-security · logging-audit
    │                     frontend-security · docker-security · cloud-security
    │                     ssh-server · devsecops · ai-security · publish-safety
    │                     http-edge-security · realtime-security · sso-federation
    │                     browser-platform-security · deserialization-security · redis-security
    │                     email-security · http-client-security
    ├── advanced/         security-testing · incident-response · network-security
    │                     supply-chain-security · cryptography · secure-architecture
    ├── enterprise/       kubernetes-security · compliance · windows-security
    │                     mobile-security · blockchain-security
    ├── architecture/     clean-architecture · ddd · hexagonal · cqrs · event-driven
    │                     modular-monolith · microservices · design-patterns
    │                     scalability · performance
    └── shared/           checklists · prompts · references · templates
```

The split between `README.md` and `AI_INSTRUCTIONS.md` is deliberate. Humans want to know
what this is and whether it is worth using; an assistant wants a routing table and a set of
rules. Mixing the two makes both worse, and makes the AI-facing part hard to grow as skills
accumulate.

## Standards

Pinned with the date each was verified against its source, because category IDs move between
editions and a stale ID is worse than no ID.

| Standard | Version | Verified | Source |
|---|---|---|---|
| OWASP Top 10 | 2025 | 2026-07-28 | <https://owasp.org/Top10/2025/> |
| OWASP API Security Top 10 | 2023 | 2026-07-28 | <https://owasp.org/API-Security/> |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28 | <https://owasp.org/www-project-application-security-verification-standard/> |

Each serves a different purpose, and the skill says which to reach for:

- **Top 10** - risk triage, and talking to people who are not security specialists
- **API Security Top 10** - anything with an API surface, where object-level authorization
  dominates
- **ASVS** - verification. Concrete, testable requirements, organised in chapters V1-V17

Top 10 tells you what usually goes wrong. ASVS tells you what to check.

If you are carrying over notes written against the 2021 Top 10, read
[the 2025 reference](skills/core/owasp/references/owasp-top10-2025.md) first. It is not a
renumbering: two categories are new and Injection moved.

## Limitations

Worth being direct about, because a security tool that oversells itself is a liability.

- **Guidance, not a scanner.** No dataflow analysis. Anything needing cross-file taint
  tracking will be missed. Pair this with SAST, do not replace it.
- **Reading code cannot confirm runtime configuration.** A correct control that is disabled in
  production still reads as correct here.
- **ASVS mapping is chapter-level** (V1-V17), not individual requirement IDs. Formal ASVS
  verification needs the official CSV.
- **Compliance mapping is engineering guidance, not certification.** The
  `enterprise/compliance` skill maps technical controls to evidence for ISO 27001, SOC 2,
  PCI DSS, HIPAA, and GDPR. It does not replace legal advice, an auditor, or the official
  framework text.
- **Example languages are Python, TypeScript, JavaScript, Java, and PHP.** The patterns
  generalise; the syntax does not.

## Security notes

The skills contain deliberately vulnerable code, used to show what a fix is fixing. Every such
block is labelled `Vulnerable:` and paired with a corrected version. Do not copy a
labelled-vulnerable block into a project.

All examples use placeholder values. No real credentials, hostnames, keys, or personal data
anywhere in this repository.

## Contributing

A new skill matches the file shape above and clears the bar `core/owasp` sets:

- Every control cites a standard - Top 10 category, ASVS chapter, and CWE where one applies
- Every pattern shows vulnerable and fixed code, and explains why the fix closes the hole
  rather than just looking safer
- Limitations are stated. A control with a known gap says so
- Version-specific claims carry the source URL and the date checked
- Nothing is invented. An unverifiable requirement number is left out, not guessed

Start from [skills/shared/templates/](skills/shared/templates/) and read
[skills/core/owasp/](skills/core/owasp/) first - the shape is easier to match than to
describe. Update [catalog/skills.json](catalog/skills.json), run
`python scripts/validate_repository.py`, then update the registry, graph, matrix, status table,
and `CHANGELOG.md`. See [CONTRIBUTING.md](CONTRIBUTING.md), [MAINTENANCE.md](MAINTENANCE.md),
[SECURITY.md](SECURITY.md), and [docs/ADOPTION.md](docs/ADOPTION.md). The adoption guide also
lists companion controls the toolkit does not replace and provides
[threat-model](docs/templates/threat-model.md) and
[security-design-review](docs/templates/security-design-review.md) templates.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Cheat Sheet Series - <https://cheatsheetseries.owasp.org/>
- CWE Top 25 - <https://cwe.mitre.org/top25/>
- NIST SSDF (SP 800-218) - <https://csrc.nist.gov/publications/detail/sp/800-218/final>

## License

MIT. See [LICENSE](LICENSE).
