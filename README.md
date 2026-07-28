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
> [AI_INSTRUCTIONS.md](AI_INSTRUCTIONS.md) — that is the machine-facing entry point, with the
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

The workflow inside `SKILL.md` is five steps — scope, map, apply, verify, report — and the
verify step is the one that matters most in practice. It is what turns "here is some code"
into "here is some code, and here is what I checked and what I could not."

## Status

All 39 skills are written end to end. Every skill includes its workflow, checklist, real
vulnerable/fixed code, limitations, and version-pinned references.

| Area | State |
|---|---|
| `core/*` (18) | Complete |
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

Nothing to install. Two ways to wire it up.

**Copy one skill into Claude Code:**

```bash
git clone https://github.com/<your-org>/secure-ai-toolkit.git
cp -r secure-ai-toolkit/skills/core/owasp ~/.claude/skills/owasp-security
```

**Or keep the repository in your project** and let the assistant read
`skills/core/owasp/SKILL.md` in place. Add `AI_INSTRUCTIONS.md` to whatever your assistant
loads at startup and it will route itself.

Other assistants — Cursor, Copilot, Codex CLI, Gemini CLI, Continue, Cline, Roo Code, Kiro —
read Markdown from their own rules or context directories. The skill files work anywhere a
Markdown instruction file is accepted. Only the YAML frontmatter in `SKILL.md` is Claude Code
specific, and it is inert elsewhere.

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

- **Top 10** — risk triage, and talking to people who are not security specialists
- **API Security Top 10** — anything with an API surface, where object-level authorization
  dominates
- **ASVS** — verification. Concrete, testable requirements, organised in chapters V1–V17

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
- **ASVS mapping is chapter-level** (V1–V17), not individual requirement IDs. Formal ASVS
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

- Every control cites a standard — Top 10 category, ASVS chapter, and CWE where one applies
- Every pattern shows vulnerable and fixed code, and explains why the fix closes the hole
  rather than just looking safer
- Limitations are stated. A control with a known gap says so
- Version-specific claims carry the source URL and the date checked
- Nothing is invented. An unverifiable requirement number is left out, not guessed

Start from [skills/shared/templates/](skills/shared/templates/) and read
[skills/core/owasp/](skills/core/owasp/) first — the shape is easier to match than to
describe. When you add a skill, add its row to the registry in
[AI_INSTRUCTIONS.md](AI_INSTRUCTIONS.md), update the status table above, and add a
`CHANGELOG.md` entry.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Cheat Sheet Series — <https://cheatsheetseries.owasp.org/>
- CWE Top 25 — <https://cwe.mitre.org/top25/>
- NIST SSDF (SP 800-218) — <https://csrc.nist.gov/publications/detail/sp/800-218/final>

## License

MIT. See [LICENSE](LICENSE).
