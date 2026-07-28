---
name: owasp
description: 'Apply OWASP standards when writing, reviewing, or designing code. Maps work to OWASP Top 10 2025, API Security Top 10 2023, and ASVS 5.0. Triggers: "OWASP", "secure code", "vulnerability", "threat model", "ASVS", "security review", "bảo mật", "lỗ hổng".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# OWASP Security

Turn OWASP standards into concrete decisions during design, implementation, and review.

## When to Use

- Writing code that touches auth, data access, file handling, or external requests
- Reviewing a diff or a codebase for vulnerabilities
- Designing a new service or API and choosing controls
- Threat modelling a feature
- Mapping a finding to a standard (Top 10 category, ASVS requirement, CWE)

## The Three Standards, and What Each Is For

| Standard | Use it for | Version here |
|---|---|---|
| Top 10 | Prioritising risk, communicating with non-specialists | 2025 |
| API Security Top 10 | Anything with an API surface (REST, GraphQL, gRPC) | 2023 |
| ASVS | Verification. Concrete, testable requirements | 5.0.0 |

Top 10 tells you what usually goes wrong. ASVS tells you what to check. Use Top 10 to
triage, ASVS to verify.

## Workflow

### 1. Scope

Identify what the change actually touches. Ask three questions:

- What data crosses a trust boundary?
- Who is allowed to do this, and where is that enforced?
- What happens on failure?

If you cannot answer all three, read the code before writing any.

### 2. Map

Pick the relevant categories rather than reciting all ten. A file upload endpoint is
A01 (access control), A02 (misconfiguration), and ASVS V5 (File Handling). It is almost
never A04 (cryptographic failures).

See [references/owasp-top10-2025.md](references/owasp-top10-2025.md) for the category
list with the questions each one implies.

### 3. Apply Controls

Work from the design outward:

1. **Authorization first.** Every object access checks ownership server-side. See
   [best-practices.md](best-practices.md#authorization).
2. **Validate at the boundary.** Allowlist, not denylist. Types and ranges, not regex
   guessing.
3. **Encode at the sink.** HTML, SQL, shell, and LDAP each need their own encoding.
   Context matters more than the input.
4. **Fail closed.** An error in an authorization check denies access.
5. **Log the decision, not the secret.**

### 4. Verify

Run [checklist.md](checklist.md) before returning code. Every unchecked box is either a
fix or a stated limitation. Do not silently skip one.

### 5. Report

For each finding: category, location, why it is exploitable, and the fix. A finding
without an exploitation path is a code smell, not a vulnerability. Say which it is.

## Severity

Rank by exploitability and blast radius, not by category name.

- **Critical** — unauthenticated access to other users' data or code execution
- **High** — authenticated privilege escalation, injection behind auth
- **Medium** — needs an unlikely precondition, or leaks non-sensitive detail
- **Low** — defence in depth missing, no direct path

State your reasoning. "SQL injection, therefore critical" is wrong if the endpoint is
admin-only and the parameter is an integer cast.

## Related Skills

- `secure-code-review` — reviewing existing code in depth
- `api-security` — API-specific controls
- `authentication` — auth flows and session handling

## Supporting Files

- [README.md](README.md) — purpose, configuration, limitations
- [checklist.md](checklist.md) — pre-return verification
- [best-practices.md](best-practices.md) — patterns that hold up
- [common-mistakes.md](common-mistakes.md) — what goes wrong, with fixes
- [troubleshooting.md](troubleshooting.md) — when the guidance conflicts
- [prompts.md](prompts.md) — prompt examples
- [references/](references/) — standard summaries with source links
- [examples/](examples/) — vulnerable and fixed code side by side
