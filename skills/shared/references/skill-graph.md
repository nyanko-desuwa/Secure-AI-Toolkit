# Skill Graph

Which skills a change needs loaded together, and in what order. One row per skill, three
relationships:

| Relationship | Meaning |
|---|---|
| `depends_on` | Load this first. The skill assumes its guidance and does not restate it. Skipping it produces a partial review. |
| `related` | Load when the change also touches that boundary. Useful, not assumed. |
| `loads` | Supporting files the skill's workflow points at directly. |

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

## Core

| Skill | depends_on | related | loads |
|---|---|---|---|
| `common-pitfalls` | — | `secrets-management`, `frontend-security`, `api-security`, `database-security`, `logging-audit`, `architecture/performance` | own `references/secret-exposure.md`, `references/resource-limits.md` |
| `owasp` | — | `secure-code-review`, `api-security`, `authentication` | `shared/references/README.md` |
| `secure-code-review` | `owasp` | `api-security`, `authentication`, `devsecops` | `shared/checklists/README.md` |
| `api-security` | `owasp` | `authentication`, `logging-audit`, `secure-code-review`, `brute-force-defense`, `architecture/performance`, `http-edge-security`, `realtime-security`, `sso-federation`, `deserialization-security`, `browser-platform-security` | own `references/api-top10-2023.md` |
| `mvc-security` | `owasp` | `api-security`, `frontend-security`, `database-security`, `secure-code-review`, `deserialization-security` | — |
| `database-security` | `owasp` | `secrets-management`, `logging-audit`, `api-security`, `redis-security` | — |
| `authentication` | `owasp` | `api-security`, `secure-code-review`, `secrets-management`, `brute-force-defense`, `realtime-security`, `sso-federation`, `redis-security` | own `references/nist-800-63b.md` |
| `brute-force-defense` | `authentication` | `api-security`, `logging-audit`, `advanced/cryptography`, `advanced/incident-response`, `ssh-server`, `redis-security` | — |
| `secrets-management` | — | `devsecops`, `cloud-security`, `docker-security`, `enterprise/kubernetes-security`, `advanced/incident-response`, `logging-audit`, `publish-safety`, `redis-security` | own `references/exposure-response.md`, `references/secret-manager-comparison.md` |
| `publish-safety` | `secrets-management` | `common-pitfalls`, `devsecops`, `docker-security`, `advanced/supply-chain-security`, `advanced/incident-response`, `browser-platform-security` | `secrets-management/references/exposure-response.md`, `common-pitfalls/references/secret-exposure.md` |
| `logging-audit` | `owasp` | `secrets-management`, `advanced/incident-response`, `secure-code-review`, `devsecops`, `api-security`, `cloud-security`, `redis-security` | — |
| `frontend-security` | `owasp` | `api-security`, `authentication`, `advanced/supply-chain-security`, `common-pitfalls`, `http-edge-security`, `realtime-security`, `browser-platform-security` | — |
| `file-upload-security` | `owasp` | `cloud-security`, `frontend-security`, `api-security`, `deserialization-security` | — |
| `docker-security` | `secrets-management` | `devsecops`, `cloud-security`, `owasp`, `enterprise/kubernetes-security`, `redis-security` | — |
| `cloud-security` | `secrets-management` | `owasp`, `docker-security`, `devsecops`, `logging-audit`, `redis-security` | — |
| `ssh-server` | `secrets-management` | `docker-security`, `devsecops`, `cloud-security`, `logging-audit` | — |
| `devsecops` | `secrets-management` | `advanced/supply-chain-security`, `docker-security`, `cloud-security`, `owasp`, `publish-safety` | own `references/tooling-matrix.md`, `references/slsa-levels.md` |
| `ai-security` | `owasp` | `api-security`, `secrets-management`, `advanced/supply-chain-security` | own `references/llm-top10.md`, `references/mcp-security.md` |
| `http-edge-security` | `owasp` | `api-security`, `frontend-security`, `ssh-server` | own `references/owasp-edge.md`, `references/asvs-edge.md` |
| `redis-security` | — | `authentication`, `brute-force-defense`, `secrets-management`, `logging-audit`, `database-security`, `docker-security`, `cloud-security`, `advanced/network-security`, `advanced/incident-response`, `scalability`, `event-driven` | own `references/redis-valkey.md`, `references/owasp-asvs-cwe.md` |
| `realtime-security` | `owasp` | `api-security`, `authentication`, `frontend-security`, `logging-audit` | own `references/realtime-threats.md`, `references/asvs-realtime.md` |
| `sso-federation` | `authentication` | `api-security`, `deserialization-security`, `logging-audit` | own `references/saml-controls.md`, `references/asvs-sso.md` |
| `browser-platform-security` | `owasp` | `frontend-security`, `publish-safety`, `api-security` | own `references/service-workers.md`, `references/extensions-pwa.md` |
| `deserialization-security` | `owasp` | `api-security`, `file-upload-security`, `mvc-security`, `sso-federation` | own `references/cwe-502.md`, `references/xxe-and-yaml.md` |

## Advanced

| Skill | depends_on | related | loads |
|---|---|---|---|
| `cryptography` | — | `core/secrets-management`, `core/authentication`, `core/api-security`, `core/cloud-security`, `core/ssh-server` | own `references/` (FIPS, SP 800-57) |
| `network-security` | `core/owasp` | `cryptography`, `core/cloud-security`, `secure-architecture`, `core/redis-security` | — |
| `security-testing` | `core/secure-code-review` | `core/devsecops`, `core/api-security`, `incident-response` | — |
| `incident-response` | `core/logging-audit` | `enterprise/compliance`, `core/secrets-management`, `supply-chain-security`, `core/owasp`, `core/redis-security` | `secrets-management/references/exposure-response.md` |
| `supply-chain-security` | `core/devsecops` | `core/owasp`, `core/secrets-management`, `core/docker-security`, `core/cloud-security`, `incident-response`, `core/publish-safety` | — |
| `secure-architecture` | `core/owasp` | `core/devsecops`, `supply-chain-security`, `core/cloud-security`, `core/authentication` | — |

## Enterprise

| Skill | depends_on | related | loads |
|---|---|---|---|
| `kubernetes-security` | `core/docker-security`, `core/secrets-management` | `core/owasp`, `compliance`, `core/cloud-security` | — |
| `windows-security` | `core/owasp` | `core/ssh-server`, `core/logging-audit`, `core/secrets-management`, `core/mvc-security`, `advanced/network-security`, `compliance` | — |
| `mobile-security` | `core/owasp` | `core/authentication`, `core/api-security`, `core/publish-safety` | own MASVS reference |
| `blockchain-security` | `core/owasp` | `core/api-security`, `core/secrets-management` | — |
| `compliance` | `core/logging-audit` | `advanced/incident-response`, `core/secrets-management`, `core/database-security`, `core/cloud-security`, `core/owasp`, `core/ai-security` | — |

## Architecture

| Skill | depends_on | related | loads |
|---|---|---|---|
| `clean-architecture` | — | `core/owasp`, `core/api-security`, `advanced/secure-architecture`, `performance`, `hexagonal`, `ddd`, `cqrs` | — |
| `hexagonal` | `clean-architecture` | `core/owasp`, `core/api-security`, `core/database-security`, `performance`, `scalability` | — |
| `ddd` | — | `core/owasp`, `advanced/secure-architecture`, `cqrs`, `performance`, `core/database-security`, `event-driven` | — |
| `cqrs` | `ddd` | `core/owasp`, `core/api-security`, `core/database-security`, `performance`, `scalability`, `event-driven` | — |
| `event-driven` | — | `core/owasp`, `core/api-security`, `performance`, `scalability`, `advanced/secure-architecture`, `core/redis-security` | — |
| `modular-monolith` | — | `clean-architecture`, `ddd`, `microservices`, `core/owasp` | — |
| `microservices` | — | `modular-monolith`, `core/api-security`, `advanced/secure-architecture`, `scalability`, `event-driven` | — |
| `design-patterns` | — | `clean-architecture`, `performance`, `core/owasp` | — |
| `performance` | — | `core/owasp`, `core/database-security`, `scalability`, `core/api-security`, `core/common-pitfalls` | own `references/` limits tables |
| `scalability` | `performance` | `event-driven`, `core/api-security`, `core/database-security`, `core/redis-security` | — |

## Reading the graph in practice

A request to build a login form:

```text
authentication            primary
  └── owasp               depends_on
brute-force-defense       related — the endpoint accepts a guessable secret
database-security         related — credentials are stored and queried
secrets-management        related — a signing key exists
```

Four core skills, one dependency edge. Inside budget.

A request to publish a package:

```text
publish-safety            primary
  └── secrets-management  depends_on
devsecops                 related — if CI does the publishing
```

Two skills and a dependency. The `advanced/supply-chain-security` edge is `related`, not
`depends_on`, because signing is a separate decision from not leaking — load it only if the request
is about provenance.

## Adding a skill to the graph

A new skill adds one row. Fill all three columns:

- `depends_on` — only where the new skill genuinely assumes the other's guidance and does not
  restate it. Empty is a valid and common answer. An over-long `depends_on` list forces every
  reader over the loading budget.
- `related` — the adjacent boundaries. Mirror the entry in the new skill's `Related Skills`
  section, using canonical directory names.
- `loads` — cross-skill files the workflow points at, so context is not spent discovering them.

Then add the reverse edge to the other skill's `related` list here. A one-directional relationship
in this table is usually an oversight.
