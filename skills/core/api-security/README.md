# API Security Skill

Controls for API surfaces: REST, GraphQL, gRPC, and webhooks in both directions.

## Purpose

APIs fail differently from web applications. There is no browser to lean on, no template to
escape into, and the client is whatever the attacker wrote. The dominant failures are
authorization ones — the wrong object, the wrong field, the wrong operation — and they are
invisible to a scanner that does not know who should own what.

This skill owns the OWASP API Security Top 10 2023 in depth. The `owasp` skill summarises that
list; this one carries the per-category questions, the controls, and code for each.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the five steps
(enumerate the surface, ask four questions per operation, apply controls in order, verify,
report), and opens the supporting file it needs.

```text
SKILL.md                   workflow, severity, category table, entry point
README.md                  this file
checklist.md               pre-return verification, grouped by API category
best-practices.md          patterns, each with a vulnerable/fixed pair
common-mistakes.md         what goes wrong and why the fix works
troubleshooting.md         when the guidance conflicts or cannot be applied
prompts.md                 prompts that produce findings, plus anti-patterns
references/
  api-top10-2023.md        the ten categories, questions and controls per category
  asvs-v4-api.md           ASVS 5.0 V4 requirement text, plus the V8 IDs that apply
examples/
  README.md                eight vulnerable/fixed pairs with category and CWE
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP API Security Top 10 | 2023 | 2026-07-28, against `OWASP/API-Security` `editions/2023/en/` |
| OWASP ASVS | 5.0.0 (released May 2025) | 2026-07-28, V4 and V8 text read from `OWASP/ASVS` `5.0/en/` |
| OWASP Top 10 | 2025 | Used only for cross-reporting. See the `owasp` skill |
| CWE | MITRE, as cited by OWASP per category | 2026-07-28 |

ASVS requirement IDs in `references/` were read from the 5.0 source files, not recalled. IDs do
not carry over from 4.0.3 — a `4.1.1` from an old report is a different requirement.

## Configuration

None. No build step, no dependency, no environment variable.

Keep this repository in the working directory so `skills/core/api-security/SKILL.md` is
readable, or copy the `api-security` directory into `~/.claude/skills/`. The frontmatter
`allowed-tools` limits it to read, search, web lookup, `ls`, and `cat`.

## Example Usage

Scope a review to one category, which is what produces findings rather than a recital:

```text
Read src/api/bookings.ts and check every handler for API3:2023 — broken object property level
authorization. For each one tell me the response schema, the input schema, and which
server-owned fields a caller could set. Show the exact request that exploits it.
```

Check the surface, not the documentation:

```text
Enumerate every route, method, and GraphQL operation reachable in this repo. Flag anything not
in the OpenAPI spec, anything versioned v1 while v2 exists, and any route with no auth guard.
```

More in [prompts.md](prompts.md).

## Limitations

- Guidance, not a scanner. No dataflow analysis. It cannot tell you that a field reaches a
  response three call frames away. Pair it with SAST and with an authorization test suite.
- Cannot see runtime configuration. Whether rate limiting is actually enabled at the gateway,
  whether TLS is enforced between internal services, whether `v1` is still routable — none of
  that is visible in application code. Those checks belong in an infrastructure review.
- Business flow risk (API6) cannot be derived from code. Which flows harm the business is a
  product decision. This skill can tell you the flow is unprotected; it cannot tell you whether
  that matters for your business.
- Examples are TypeScript, Python, Go, and Java. gRPC coverage is thinner than REST, and
  reflects the interceptor pattern rather than any one framework's idioms.
- ASVS citations are chapter-level except where a specific ID was read from the 5.0 source. For
  a formal ASVS assessment, work from the official requirement set.
- No coverage of API gateway product configuration, service mesh policy, or WAF rule authoring.
- WebSocket is mentioned only where ASVS V4.4 applies. It is not an API surface this skill
  treats in depth.

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md`, `common-mistakes.md`,
and `examples/`. Every such block is labelled `Vulnerable:` and paired with a fixed version. Do
not copy a labelled-vulnerable block into a project.

All hostnames, keys, and identifiers are placeholders. `sk_test_...`, `hooks.example.com`, and
similar values are not real and are not valid anywhere.

## References

- OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- REST Security Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- Mass Assignment Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>
- GraphQL Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- OWASP Automated Threats to Web Applications — <https://owasp.org/www-project-automated-threats-to-web-applications/>
