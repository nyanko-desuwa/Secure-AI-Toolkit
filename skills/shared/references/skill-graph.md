# Skill Graph

Which skills a change needs loaded together, and in what order. One row per skill, three
relationships:

| Relationship | Meaning |
|---|---|
| `depends_on` | Load this first. The skill assumes its guidance and does not restate it. Skipping it produces a partial review. |
| `related` | Load when the change also touches that boundary. Useful, not assumed. |
| `conflicts` | Do not load both for the same decision; they give opposing guidance. Must be symmetric. |
| `loads` | Supporting files the skill's workflow points at directly. |

The machine-readable form of these edges lives in each skill's `skill.yaml` (`requires` =
`depends_on`, `suggests` = `related`, plus `conflicts`), generated from the catalog. This table is
the human-readable view of the same graph. The validator enforces: no `depends_on` cycle, no
dangling edge to a non-existent skill, and symmetric `conflicts`; a one-directional `related`
without its reverse is reported as an advisory count, not a failure.

`depends_on` is the column that matters. A `docker-security` review that never loaded
`secrets-management` will miss the build-arg credential, because `docker-security` treats that
question as already answered elsewhere.

Canonical names are directory names. Some skills' own `Related Skills` sections use informal
aliases (`owasp-security` for `owasp`, `logging-monitoring` for `logging-audit`); this file is the
authoritative list, and a name that does not appear in the left column below does not exist.

## Loading budget

The rule in `AI_INSTRUCTIONS.md` caps a single task at five core, two advanced, one enterprise, and
one architecture skill. `depends_on` counts against that budget. If a chain would exceed it, load
the primary skill plus its direct `depends_on`, then name what you did not load and why.

Depth is capped at two: load a skill's `depends_on`, and their `depends_on`, and stop. Transitive
closure on this graph reaches most of the repository, which is the outcome the budget exists to
prevent.

<!-- GENERATED SKILL GRAPH: START -->

## Core

| Skill | depends_on | related | loads |
|---|---|---|---|
| `ai-security` | `owasp` | `api-security`, `secrets-management`, `supply-chain-security`, `email-security`, `http-client-security` | own `references/llm-top10.md`, `references/mcp-security.md` |
| `api-security` | `owasp` | `authentication`, `logging-audit`, `secure-code-review`, `brute-force-defense`, `performance`, `email-security`, `http-client-security` | own `references/api-top10-2023.md` |
| `authentication` | `owasp` | `api-security`, `secure-code-review`, `secrets-management`, `brute-force-defense`, `email-security` | own `references/nist-800-63b.md` |
| `browser-platform-security` | `owasp` | `frontend-security`, `publish-safety`, `api-security` | own `references/service-workers.md`, own `references/extensions-pwa.md` |
| `brute-force-defense` | `authentication` | `api-security`, `logging-audit`, `cryptography`, `incident-response`, `ssh-server`, `email-security` | - |
| `cloud-security` | `secrets-management` | `owasp`, `docker-security`, `devsecops`, `logging-audit`, `http-client-security` | - |
| `common-pitfalls` | - | `secrets-management`, `frontend-security`, `api-security`, `database-security`, `logging-audit`, `performance` | own `references/secret-exposure.md`, `references/resource-limits.md` |
| `database-security` | `owasp` | `secrets-management`, `logging-audit`, `api-security` | - |
| `deserialization-security` | `owasp` | `api-security`, `file-upload-security`, `mvc-security`, `email-security`, `http-client-security` | own `references/cwe-502.md`, own `references/xxe-and-yaml.md` |
| `devsecops` | `secrets-management` | `supply-chain-security`, `docker-security`, `cloud-security`, `owasp`, `publish-safety` | own `references/tooling-matrix.md`, `references/slsa-levels.md` |
| `docker-security` | `secrets-management` | `devsecops`, `cloud-security`, `owasp`, `kubernetes-security` | - |
| `file-upload-security` | `owasp` | `cloud-security`, `frontend-security`, `api-security`, `email-security` | - |
| `frontend-security` | `owasp` | `api-security`, `authentication`, `supply-chain-security`, `common-pitfalls` | - |
| `http-edge-security` | `owasp` | `api-security`, `frontend-security`, `ssh-server`, `email-security`, `http-client-security` | own `references/owasp-edge.md`, own `references/asvs-edge.md` |
| `logging-audit` | `owasp` | `secrets-management`, `incident-response`, `secure-code-review`, `devsecops`, `api-security`, `cloud-security`, `email-security`, `http-client-security` | - |
| `mvc-security` | `owasp` | `api-security`, `frontend-security`, `database-security`, `secure-code-review` | - |
| `owasp` | - | `secure-code-review`, `api-security`, `authentication` | `shared/references/README.md` |
| `publish-safety` | `secrets-management` | `common-pitfalls`, `devsecops`, `docker-security`, `supply-chain-security`, `incident-response` | `secrets-management/references/exposure-response.md`, `common-pitfalls/references/secret-exposure.md` |
| `redis-security` | - | `authentication`, `brute-force-defense`, `secrets-management`, `logging-audit`, `database-security`, `docker-security`, `cloud-security`, `network-security`, `incident-response`, `scalability`, `event-driven` | own `references/redis-valkey.md`, own `references/owasp-asvs-cwe.md` |
| `realtime-security` | `owasp` | `api-security`, `authentication`, `frontend-security`, `logging-audit` | own `references/realtime-threats.md`, own `references/asvs-realtime.md` |
| `secrets-management` | - | `devsecops`, `cloud-security`, `docker-security`, `kubernetes-security`, `incident-response`, `logging-audit`, `publish-safety`, `email-security`, `http-client-security` | own `references/exposure-response.md`, `references/secret-manager-comparison.md` |
| `secure-code-review` | `owasp` | `api-security`, `authentication`, `devsecops` | `shared/checklists/README.md` |
| `ssh-server` | `secrets-management` | `docker-security`, `devsecops`, `cloud-security`, `logging-audit` | - |
| `sso-federation` | `authentication` | `api-security`, `deserialization-security`, `logging-audit` | own `references/saml-controls.md`, own `references/asvs-sso.md` |
| `email-security` | `owasp` | `authentication`, `brute-force-defense`, `api-security`, `http-client-security`, `http-edge-security`, `secrets-management`, `logging-audit`, `file-upload-security`, `deserialization-security`, `event-driven`, `ai-security` | own `references/email-standards.md`, own `references/owasp-asvs.md` |
| `http-client-security` | `owasp` | `api-security`, `http-edge-security`, `network-security`, `cloud-security`, `cryptography`, `secrets-management`, `logging-audit`, `performance`, `microservices`, `event-driven`, `ai-security`, `deserialization-security`, `email-security` | own `references/owasp-asvs.md`, own `references/http-uri-tls.md` |

## Advanced

| Skill | depends_on | related | loads |
|---|---|---|---|
| `cryptography` | - | `secrets-management`, `authentication`, `api-security`, `cloud-security`, `ssh-server`, `http-client-security` | own `references/` (FIPS, SP 800-57) |
| `incident-response` | `logging-audit` | `compliance`, `secrets-management`, `supply-chain-security`, `owasp` | `secrets-management/references/exposure-response.md` |
| `network-security` | `owasp` | `cryptography`, `cloud-security`, `secure-architecture`, `http-client-security` | - |
| `secure-architecture` | `owasp` | `devsecops`, `supply-chain-security`, `cloud-security`, `authentication` | - |
| `security-testing` | `secure-code-review` | `devsecops`, `api-security`, `incident-response` | - |
| `supply-chain-security` | `devsecops` | `owasp`, `secrets-management`, `docker-security`, `cloud-security`, `incident-response`, `publish-safety` | - |

## Enterprise

| Skill | depends_on | related | loads |
|---|---|---|---|
| `blockchain-security` | `owasp` | `api-security`, `secrets-management` | - |
| `compliance` | `logging-audit` | `incident-response`, `secrets-management`, `database-security`, `cloud-security`, `owasp`, `ai-security` | - |
| `kubernetes-security` | `docker-security`, `secrets-management` | `owasp`, `compliance`, `cloud-security` | - |
| `mobile-security` | `owasp` | `authentication`, `api-security`, `publish-safety` | own MASVS reference |
| `windows-security` | `owasp` | `ssh-server`, `logging-audit`, `secrets-management`, `mvc-security`, `network-security`, `compliance` | - |
| `payments-security` | `owasp` | `secrets-management`, `logging-audit`, `api-security`, `brute-force-defense`, `compliance`, `publish-safety`, `kubernetes-security` | own references/ (PCI DSS 4.0, 3DS 2.x) |

## Architecture

| Skill | depends_on | related | loads |
|---|---|---|---|
| `clean-architecture` | - | `owasp`, `api-security`, `secure-architecture`, `performance`, `hexagonal`, `ddd`, `cqrs` | - |
| `cqrs` | `ddd` | `owasp`, `api-security`, `database-security`, `performance`, `scalability`, `event-driven` | - |
| `ddd` | - | `owasp`, `secure-architecture`, `cqrs`, `performance`, `database-security`, `event-driven` | - |
| `design-patterns` | - | `clean-architecture`, `performance`, `owasp` | - |
| `event-driven` | - | `owasp`, `api-security`, `performance`, `scalability`, `secure-architecture`, `email-security`, `http-client-security` | - |
| `hexagonal` | `clean-architecture` | `owasp`, `api-security`, `database-security`, `performance`, `scalability` | - |
| `microservices` | - | `modular-monolith`, `api-security`, `secure-architecture`, `scalability`, `event-driven`, `http-client-security` | - |
| `modular-monolith` | - | `clean-architecture`, `ddd`, `microservices`, `owasp` | - |
| `performance` | - | `owasp`, `database-security`, `scalability`, `api-security`, `common-pitfalls`, `http-client-security` | own `references/` limits tables |
| `scalability` | `performance` | `event-driven`, `api-security`, `database-security` | - |

<!-- GENERATED SKILL GRAPH: END -->

## Reading the graph in practice

A request to build a login form:

```text
authentication            primary
  \-- owasp               depends_on
brute-force-defense       related - the endpoint accepts a guessable secret
database-security         related - credentials are stored and queried
secrets-management        related - a signing key exists
```

Four core skills, one dependency edge. Inside budget.

A request to publish a package:

```text
publish-safety            primary
  \-- secrets-management  depends_on
devsecops                 related - if CI does the publishing
```

Two skills and a dependency. The `advanced/supply-chain-security` edge is `related`, not
`depends_on`, because signing is a separate decision from not leaking - load it only if the request
is about provenance.

## Adding a skill to the graph

A new skill adds one row. Fill all three columns:

- `depends_on` - only where the new skill genuinely assumes the other's guidance and does not
  restate it. Empty is a valid and common answer. An over-long `depends_on` list forces every
  reader over the loading budget.
- `related` - the adjacent boundaries. Mirror the entry in the new skill's `Related Skills`
  section, using canonical directory names.
- `loads` - cross-skill files the workflow points at, so context is not spent discovering them.

Then add the reverse edge to the other skill's `related` list here. A one-directional relationship
in this table is usually an oversight.
