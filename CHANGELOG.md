# Changelog

Notable changes to this repository. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
