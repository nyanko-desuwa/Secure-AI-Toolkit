# Changelog

Notable changes to this repository. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `core/redis-security` skill — Redis OSS 7.x/8.x and Valkey 8.x service-boundary hardening: private reachability, ACLs, TLS, persistence and backups, Redis 8 integrated modules, Sentinel/Cluster, eviction, Redis-backed session/cache/queue/limiter roles, framework integration, real incident lessons, and operations telemetry. Grounded in official Redis/Valkey documentation, OWASP Top 10 2025, ASVS 5.0.0, and CWE mappings.
- Canonical `catalog/skills.json` and schema, repository validator, cross-platform skill installer
  and release helpers, GitHub Actions validation/secret-scan/release workflows, Dependabot, and
  Gitleaks configuration. The tag workflow creates a GitHub Release from the matching changelog
  section after validation succeeds.
- Least-privilege `research-only` frontmatter for every production skill and the scaffold.
- `SECURITY.md`, `MAINTENANCE.md`, `CONTRIBUTING.md`, and `docs/ADOPTION.md`; durable release rules
  now live there and in `scripts/README.md`.
- Five core skills: `http-edge-security`, `realtime-security`, `sso-federation`,
  `browser-platform-security`, and `deserialization-security`. They cover HTTP edge trust,
  WebSocket/SSE/WebRTC, SAML federation, browser platform capabilities, and unsafe parsing.

### Changed

- Root `README.md` — the two-line "copy one skill" note becomes a full
  `## Installing as Claude Code skills` section: personal vs project scope, why the four
  category directories have to be flattened, install-a-few / install-all-45 / symlink /
  committed-per-project variants, how to confirm with `/skills`, and the startup context cost
  of installing the whole set. Verified against <https://code.claude.com/docs/en/skills> on
  2026-07-28. The clone URL now points at the real repository instead of `<your-org>`.

## [1.0.1] - 2026-07-28

### Added

- `core/publish-safety` skill — the publish boundary as a control point of its own. Thirteen
  files covering git push and repository visibility, package and container registries, static
  hosting and build output, mobile bundles, and the human channels (PR diffs, issues,
  screenshots, pasted logs, AI prompts). Grounded in OWASP Top 10 2025 A02/A03/A04/A08,
  ASVS 5.0 V13/V14/V15, and CWE-527, CWE-540, CWE-538, CWE-798, CWE-615, CWE-532 — each CWE
  fetched from cwe.mitre.org on 2026-07-28.
- A mandatory pre-publish gate in `AI_INSTRUCTIONS.md` (`## Before you publish anything`, plus
  rule 11). It binds the assistant working in a consumer's project: run the checklist before any
  publishing command, stage named paths rather than `git add -A`, stop on any hit, and never
  rewrite history or force-push to clean up a leak. It grants exactly one write authority —
  creating or editing the user's ignore files and generating `.env.example` by stripping values,
  with a line-by-line report of what was added.
- `skills/shared/references/skill-graph.md` — central `depends_on` / `related` / `loads` table
  for all 39 skills. Dependency metadata lives here rather than in per-skill frontmatter, so a
  reader can see the whole graph without opening 39 files.
- `skills/shared/references/standards-matrix.md` — skill × standard coverage, so "which skill
  covers A03:2025" is a lookup rather than a search.
- A `## Loading budget` section and a `## Before you return` self-review order in
  `AI_INSTRUCTIONS.md`. The budget caps a task at five `core/`, two `advanced/`, one
  `enterprise/`, and one `architecture/` skill, with `depends_on` counting against it.
- A content policy for new skills in `skills/shared/templates/README.md`: seven example pairs,
  four prompt tiers, a `When NOT to Use` routing table, named framework coverage, and the
  reference and deprecation rules.
- `RELEASING.md` — version rules for a documentation repository, the tag and release sequence,
  and the rule that a standards pin moves in three places together. Superseded by
  `MAINTENANCE.md`, `CONTRIBUTING.md`, and `scripts/README.md` in Unreleased.

### Changed

- `AI_INSTRUCTIONS.md` — registry row and routing row for `publish-safety`.
- Root `README.md` — 38 skills → 39, `core/*` 17 → 18, and `publish-safety` in the layout tree.
- `skills/shared/checklists/README.md` — routing row for a publish-shaped change, and a
  publish-gate line in the universal pre-return checks.
- `skills/shared/references/README.md` — pointers to the two new shared reference tables.
- `## Related Skills` cross-links added in `core/secrets-management`, `core/common-pitfalls`,
  and `core/devsecops`.
- `CHANGELOG.md` — the previously unreleased content is now `1.0.0`, which is what the initial
  two commits describe.

### Notes

- `publish-safety` links out rather than restating. The revoke/rotate/investigate order stays in
  `core/secrets-management/references/exposure-response.md`; the per-stack public env prefixes
  and build-output greps stay in `core/common-pitfalls/references/secret-exposure.md`; enforced
  pipeline scanning stays in `core/devsecops`.
- This repository's own `.gitignore`, CI, and pre-commit configuration are deliberately
  unchanged. This release adds content, not repository configuration. The new skill's
  `README.md` states that inconsistency in its limitations rather than leaving a reader to
  notice it.
- CWE-200 was considered and left out. MITRE marks it DISCOURAGED for mapping; the specific
  children are cited instead.
- The content policy applies to skills added from now on. The existing 38 are not retrofitted —
  a sweep would produce a large diff and no new guidance.

## [1.0.0] - 2026-07-28

### Added

- Repository scaffold: `skills/` tree for core, advanced, enterprise, architecture, and
  shared material.
- `core/owasp` skill, complete and serving as the reference shape for every other skill.
  Eleven files: `SKILL.md`, `README.md`, `checklist.md`, `best-practices.md`,
  `common-mistakes.md`, `troubleshooting.md`, `prompts.md`, three files under `references/`,
  and `examples/README.md`.
- Standard summaries pinned to a version and a verification date: OWASP Top 10 2025,
  OWASP API Security Top 10 2023, OWASP ASVS 5.0.0. All three checked against owasp.org on
  2026-07-28.
- Seven vulnerable/fixed example pairs in `core/owasp/examples/`, covering broken object
  level authorization, SQL injection through a sort parameter, path traversal, SSRF, failing
  open on a policy error, file upload type confusion, and JWT algorithm confusion.
- Skill scaffold under `skills/shared/templates/skill-scaffold/`, matching the reference file
  shape, plus `skills/shared/templates/README.md` describing the bar a new skill must clear.
- `AI_INSTRUCTIONS.md` — machine-facing entry point. Holds the skill registry, routing table,
  standing rules, output contract, and conflict resolution. Kept separate from `README.md` so
  the human introduction and the assistant instructions can each grow without crowding the
  other.
- Shared cross-skill routing under `skills/shared/checklists/`, reusable review prompts under
  `skills/shared/prompts/`, and a version-pinned standards index under
  `skills/shared/references/`.
- Complete core skill set, including authentication, API and database security, secrets,
  logging, containers, cloud, AI, frontend, uploads, brute-force defence, and the
  non-expert-facing `common-pitfalls` skill.
- Complete advanced skill set covering cryptography, network security, security testing,
  incident response, supply-chain security, and secure architecture.
- Complete enterprise skill set covering Kubernetes, Windows, mobile, blockchain, and
  compliance evidence mapping.
- Complete architecture guidance for clean architecture, DDD, hexagonal, CQRS,
  event-driven systems, modular monoliths, microservices, design patterns, scalability, and
  performance/resource lifetime.

### Security considerations

- The skills contain deliberately vulnerable code for teaching purposes. Every such block is
  labelled `Vulnerable:` and paired with a corrected version. Copying a labelled-vulnerable
  block into a project introduces the vulnerability it demonstrates.
- All examples use placeholder values. No real credentials, hostnames, keys, or personal data.

### Notes

- The OWASP Top 10 2025 is not a renumbering of 2021. `A03:2025 Software Supply Chain
  Failures` and `A10:2025 Mishandling of Exceptional Conditions` are new, and Injection moves
  from A03 to A05. Guidance written against 2021 category IDs will mis-map.
- No breaking changes, no migration steps: this is the initial content.

[Unreleased]: https://github.com/nyanko-desuwa/Secure-AI-Toolkit/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/nyanko-desuwa/Secure-AI-Toolkit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/nyanko-desuwa/Secure-AI-Toolkit/releases/tag/v1.0.0
