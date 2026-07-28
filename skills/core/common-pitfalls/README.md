# Common Pitfalls

The mistakes that appear in code written quickly, by an AI, for someone who will not read it
line by line. Seven families, each with the real code shape, what it costs, and a fix that
removes the unsafe option instead of relying on someone remembering.

## Purpose

The other skills in this repository assume a developer who can be told "use parameterized
queries" and will act on it. This one assumes the reader described a feature, got working code,
and shipped it. The mistake will not be caught in review, because there is no review.

That changes the guidance in three ways:

- The consequence comes first, in plain words. "Anyone who opens your site can read this key and
  spend your credits" before any explanation of how bundlers work.
- The fix has to be structural. A rule you have to remember is not a fix for someone who does
  not know the rule exists.
- Detection has to be a command you can run, not an instinct you have to develop.

## Who It Is For

Anyone shipping software they did not write themselves. Also useful as a pre-flight check for
developers, because families 3, 5, and 6 catch experienced people too.

It is a front door, not a replacement. Where a topic has its own skill, this one gives you
enough to recognise the problem and then points at the depth:

| If the finding is | Go deeper in |
|---|---|
| A leaked credential, rotation, secret storage | `secrets-management` |
| XSS, CSP, where to keep a session token | `frontend-security` |
| Object-level authorization, rate limiting design | `api-security` |
| Row Level Security, indexes, connection pools | `database-security` |
| What to log once errors stop being swallowed | `logging-audit` |

## How It Works

Plain Markdown. Nothing executes. `SKILL.md` gives a seven-step triage order; each step points
at the file that has the detail.

```text
SKILL.md                       triage workflow, severity, the seven families
README.md                      this file
checklist.md                   pre-ship checks, grouped by family
best-practices.md              the safe default per family, vulnerable/fixed pairs
common-mistakes.md             the catalogue: shape, cost, fix, why it cannot recur
troubleshooting.md             symptom-first entry points
prompts.md                     prompts that produce a real audit, plus anti-patterns
references/
  secret-exposure.md           where secrets leak per stack, detection commands
  resource-limits.md           limit, timeout, and pagination defaults
  owasp-mapping.md             family to Top 10 2025 / API Top 10 2023 / ASVS / CWE
examples/README.md             twelve vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Scope here | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A01, A02, A04, A06, A10 | 2026-07-28 |
| OWASP API Security Top 10 | 2023 | API1, API3, API4, API5, API8 | 2026-07-28 |
| OWASP ASVS | 5.0.0, released 2025-05-30 | V2, V3, V4, V8, V9, V11, V13, V14, V16 | 2026-07-28 |

CWEs used: CWE-798, CWE-259, CWE-540, CWE-615, CWE-602, CWE-807, CWE-347, CWE-295, CWE-401,
CWE-772, CWE-770, CWE-400, CWE-390, CWE-209, CWE-1188.

ASVS mapping is at chapter level. Requirement IDs are not quoted anywhere in this skill,
because they were not verified against the official requirement list.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/core/common-pitfalls/SKILL.md` is readable, or copy the directory into
`~/.claude/skills/`. The `allowed-tools` frontmatter limits it to reading, searching, and web
lookup plus `ls` and `cat`.

## Example Usage

Check whether you have already leaked a key:

```text
Build the project, then search the build output for anything that looks like a credential.
Check dist/, build/, and .next/static/. For each hit tell me which file, which key, and
whether it is in the JavaScript that browsers download. Do not check only the source.
```

Audit the security decisions:

```text
List every place this codebase decides what a user is allowed to do. For each one say whether
the decision runs on the server or in the browser, and show me the curl command that bypasses
it if it runs in the browser.
```

Find the missing limits:

```text
Find every endpoint that returns a list, every file upload, every outbound HTTP call, and
every retry loop. Tell me which have no maximum. Rank by what one request could do.
```

More in [prompts.md](prompts.md).

## Limitations

- Guidance, not a scanner. The detection commands here catch string-shaped secrets in build
  output. They will not catch a key assembled at runtime, base64-encoded, or split across
  variables. Pair them with a real secret scanner in CI.
- It cannot see your deployment. Whether the production environment variable is actually set,
  whether the Row Level Security policy is enabled on the live project, and whether the CDN is
  caching a private response are all unverifiable from source. Where a check needs the running
  system, this skill says so.
- Memory diagnosis is approximate from code alone. Distinguishing a real leak from a warming
  cache or allocator fragmentation needs measurement over time. See
  [troubleshooting.md](troubleshooting.md#memory-keeps-growing).
- Language coverage is TypeScript, JavaScript, React, Next.js, Express, and Python. The
  patterns generalise; the syntax does not. Nothing here is Go, Rust, Java, PHP, or Ruby
  specific.
- Firebase and Supabase guidance covers the shape of the mistake and the shape of the fix. It
  is not a substitute for that vendor's current rules or policy documentation, which changes.
- Performance advice here is about avoidable orders of magnitude, not tuning. It will not tell
  you which of two reasonable designs is faster.

## Security Notes

`best-practices.md`, `common-mistakes.md`, and `examples/README.md` contain deliberately broken
code. Every such block is labelled `Vulnerable:` and paired with a fixed version. Do not copy a
labelled-vulnerable block.

Every credential in this skill is an obvious placeholder. There are no real keys, hostnames, or
personal data anywhere in it.

One thing worth stating twice: a Firebase or Supabase client key being visible in your frontend
is not the vulnerability. Missing Row Level Security or missing security rules is. Both facts
are true at once, and treating the visible key as the problem leads people to hide it and leave
the database open. See
[examples/README.md](examples/README.md#supabase-anon-key-exposed-fine-no-rls-not-fine).

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Cheat Sheet Series — <https://cheatsheetseries.owasp.org/>
- CWE list — <https://cwe.mitre.org/data/index.html>
