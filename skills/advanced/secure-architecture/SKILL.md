---
name: secure-architecture
description: 'Design and review system architecture for security: trust boundaries, threat models, tenant isolation, least privilege, secure defaults, failure modes, and security ADRs. Triggers: "architecture review", "threat model", "trust boundary", "zero trust", "multi-tenant", "kiến trúc", "phân quyền".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# Secure Architecture

Decide where controls live before code exists, and find the design flaws that no diff review
will catch.

## When to Use

- Designing a new service, or changing how existing services talk to each other
- Adding a tenant, a role, or a trust relationship with a third party
- Reviewing an architecture document, IaC tree, or service topology
- Writing or reviewing a security ADR
- Something was exploited and the fix keeps needing to be applied in more places

## What This Skill Is Not

Not a code review skill. If the question is "is this query parameterized", use `core/owasp` or
`core/secure-code-review`. Architecture findings have a distinguishing property: the fix changes
where a control lives, not what a function does.

Three tests for whether a finding is architectural:

1. Fixing it in one file leaves the same bug reachable by another path.
2. The control does not exist anywhere, so there is nothing to correct.
3. The control exists but the design lets callers go around it.

## Workflow

### 1. Draw the boundaries

A trust boundary is any place where data or control crosses between components that trust each
other differently. Not every arrow is a boundary. The ones that are:

- Internet → your edge
- Your edge → your services
- One tenant's data → another tenant's request path
- Your service → a third party you do not control
- Application → build system, and build system → production
- Human operator → production data

For each boundary, name three things: what is authenticated, what is authorized, and what
happens when the check fails. If you cannot name all three, that is the finding.

See [best-practices.md](best-practices.md#trust-boundaries).

### 2. Threat model the crossings

Four questions, from the Threat Modeling Manifesto: what are we working on, what can go wrong,
what are we going to do about it, did we do a good enough job. STRIDE per boundary crossing is
the cheapest way to answer the second one. LINDDUN when personal data is involved.

See [references/threat-modeling.md](references/threat-modeling.md).

### 3. Place the controls

Order matters. Work outside-in and put each control at the lowest layer that can enforce it:

1. **Identity at the boundary.** Every crossing has an authenticated principal. Not a header,
   not a network position.
2. **Authorization next to the data.** The component holding the row decides who reads it. A
   gateway check is defence in depth, never the only check.
3. **Isolation by default.** Separate what has different privilege levels — tenants, admin
   surfaces, build and runtime.
4. **Least privilege on every identity.** Human, service, and CI. Scope to the operation, not
   the service.
5. **Secure default when config is absent.** Missing means deny.
6. **Deny on failure.** Every dependency outage has a defined answer, and it is not "allow".
7. **Audit path that cannot be bypassed.** If a mutation can happen without a record, the audit
   trail is decoration.

### 4. Work the failure modes

For each dependency: what breaks, what the caller sees, and whether security degrades. A design
that is secure only while the auth service is up is not secure. Write down the answer per
dependency — this is the part reviews skip and incidents find.

See [best-practices.md](best-practices.md#failure-modes-and-resilience).

### 5. Record the decision

A security decision that is not written down gets re-litigated and then reversed by someone with
less context. An ADR that names the threat, the options, the choice, and the accepted residual
risk survives. Template in [best-practices.md](best-practices.md#security-adrs).

### 6. Verify

Run [checklist.md](checklist.md). Unchecked items become either a change to the design or a
stated, owned residual risk. Not silence.

## Severity

Rank by blast radius and by how many places the fix has to land.

- **Critical** — a boundary that does not exist. One tenant reads another's data; a path reaches
  production data with no authenticated principal.
- **High** — a boundary enforced in exactly one bypassable place. Gateway-only authorization,
  client-side entitlement, shared credential across environments.
- **Medium** — control present but too coarse. Role grants more than the job needs; blast radius
  larger than necessary; no audit trail on a sensitive flow.
- **Low** — defence in depth missing, no current path. Missing egress restriction where nothing
  currently makes outbound calls.

State the reasoning. "No mTLS between services" is Low in a single-tenant deployment with one
namespace and Critical when the same cluster hosts an untrusted workload.

## Related Skills

- `core/owasp` — implementation-level controls and the Top 10 mapping
- `core/devsecops` — where security checks run in the pipeline, and CI as a trust boundary
- `advanced/supply-chain-security` — build integrity and provenance
- `core/cloud-security` — IAM and network primitives per provider
- `core/authentication` — token and session mechanics behind boundary identity

## Supporting Files

- [README.md](README.md) — purpose, standards, configuration, limitations
- [checklist.md](checklist.md) — pre-return verification, grouped by boundary
- [best-practices.md](best-practices.md) — patterns, with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the secure design is not available
- [prompts.md](prompts.md) — prompts that produce findings, and anti-patterns
- [references/](references/) — standards, version-pinned with check dates
- [examples/](examples/) — seven vulnerable/fixed architecture pairs
