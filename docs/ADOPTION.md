# Adoption guide

Ten-minute path from clone to a useful security review, then how to roll the pack
out to a team.

## 1. First successful review (≈10 minutes)

```bash
git clone https://github.com/nyanko-desuwa/Secure-AI-Toolkit.git
```

Point your assistant at `AI_INSTRUCTIONS.md` (see tool table below), then run a
**specific** prompt against one real file:

```text
Review src/api/invoices.py against OWASP Top 10 2025 using this toolkit's output
contract. For each finding: category, file:line, exploitation path, fix, severity.
Skip anything without an exploitation path. List which skills/checklists you used
and what you could not verify.
```

You are done when the answer names concrete locations and admits unverified
preconditions instead of padding a category recital.

### Expected shape of a good answer

- Category IDs (Top 10 / ASVS / CWE) with reasoning
- `file:line` and a real exploitation path
- A fix that closes the path, not only "looks safer"
- Explicit list of skills consulted and checks **not** run

## 2. Starter packs (install only what you need)

Claude Code discovers flat skill directories. Prefer 3-5 skills over all of them
(~14 KB of descriptions at startup for the full set).

| Project type | Install these first |
|---|---|
| General web app | `owasp`, `api-security`, `frontend-security`, `authentication`, `http-edge-security` |
| Public/JSON API | `owasp`, `api-security`, `authentication`, `brute-force-defense`, `logging-audit` |
| Real-time / WS | `realtime-security`, `api-security`, `authentication`, `frontend-security` |
| Enterprise SSO | `sso-federation`, `authentication`, `logging-audit` |
| CI / containers | `devsecops`, `docker-security`, `secrets-management`, `publish-safety`, `supply-chain-security` |
| Browser extension / PWA | `browser-platform-security`, `frontend-security`, `publish-safety` |
| Parsers / import pipelines | `deserialization-security`, `file-upload-security`, `api-security` |
| Redis-backed sessions / limiters | `redis-security`, `authentication`, `brute-force-defense`, `secrets-management`, `logging-audit` |
| AI agents / tool calling | `ai-security`, `api-security`, `secrets-management`, `authentication`, `publish-safety` |
| Transactional email / provider events | `email-security`, `authentication`, `api-security`, `secrets-management`, `logging-audit` |
| Third-party HTTP integrations | `http-client-security`, `api-security`, `network-security`, `secrets-management`, `logging-audit` |

Install helpers:

```bash
./scripts/install-skills.sh --skills owasp,api-security,frontend-security,publish-safety --verify
```

```powershell
.\scripts\Install-Skills.ps1 -Skills owasp,api-security,frontend-security,publish-safety -Verify
```

Details: [scripts/README.md](../scripts/README.md) and root [README.md](../README.md).

### Copy vs symlink updates

| Mode | Update model |
|---|---|
| **Copy** | After `git pull` in the toolkit checkout, re-copy (or re-run the installer with `--force`) |
| **Symlink** | `git pull` in the checkout updates all linked skills; Windows may need Developer Mode |

## 3. Assistant compatibility

| Tool | Verified approach in this pack | Notes |
|---|---|---|
| **Claude Code** | Install flattened skills; `/skills` to confirm | Frontmatter `allowed-tools` enforced after workspace trust |
| **Cursor** | Add `AI_INSTRUCTIONS.md` + needed `SKILL.md` paths to project rules/context | Frontmatter ignored |
| **GitHub Copilot Chat** | Reference `AI_INSTRUCTIONS.md` in custom instructions; attach skill files | No skill discovery |
| **Codex CLI / Gemini CLI** | Point instructions file at `AI_INSTRUCTIONS.md` | Load skills on demand by path |
| **Continue / Cline / Roo Code / Kiro** | Rules or context docs => `AI_INSTRUCTIONS.md` | Copy or link skill trees as the tool allows |

"Point the tool at `AI_INSTRUCTIONS.md`" always means: make that file part of the
model's standing instructions, then load individual `skills/**/SKILL.md` files
when the task matches the routing table - do not paste the entire repository.

## 4. Team rollout

1. **Pin a release tag** (`vX.Y.Z`) rather than floating `main` if you need reproducibility.
2. Choose **project-scoped** install (`.claude/skills/...` committed) for shared baselines;
   personal install for experimentation.
3. Start with the starter pack for your system type; add skills when reviews repeatedly
   hit an adjacent boundary.
4. Require the output contract in PR templates (category, location, exploit path, fix).
5. Keep **owners** for standards re-pins (see [MAINTENANCE.md](../MAINTENANCE.md)).

### Load by boundary, not by keyword

Start with the skill that owns the trust or service boundary, then add only direct related skills
that the change actually touches. Follow an ownership section's `Does not own` hand-off rather
than loading several skills that repeat the same policy. The catalog graph and the loading budget
are designed to keep this reviewable.

### Complementary controls (not replaced by this pack)

| Control | Evidence it produces | What the toolkit cannot prove |
|---|---|---|
| SAST (for example Semgrep or CodeQL) | Cross-file taint and pattern findings | Runtime reachability and deployment configuration |
| SCA / lockfile audit (Dependabot or OSV) | Known dependency and licence inventory | Whether a vulnerable dependency is exploitable in this service |
| Secret scanning (Gitleaks) | Credentials in diff or history | Rotation, revocation, and downstream exposure impact |
| DAST / authz matrix tests | Runtime behavior and BOLA evidence | Unexercised paths and business decisions not encoded in tests |
| IaC + container scan (Checkov or Trivy) | Deployed-config and image findings | Live cloud state not represented in source |
| SBOM (Syft) | Component inventory for releases | Vulnerability triage or provenance enforcement by itself |
| Threat model / design review | Control placement, boundary decisions, accepted risks | That the decision was implemented or deployed |
| External-link monitor | Stale-reference maintenance signals | That an upstream transient outage invalidates a source |

The examples name tool classes, not mandatory vendors. This toolkit supplies security reasoning,
routing, and review checklists; it does not replace scanners, runtime tests, branch protection, or
production verification.

### Design review artifacts

Use the [threat model template](templates/threat-model.md) before a material boundary change, and
the [security design review template](templates/security-design-review.md) to record the decision,
evidence, rollback path, and accepted residual risks. Both build on
[`advanced/secure-architecture`](../skills/advanced/secure-architecture/SKILL.md).

CODEOWNERS requests the relevant review only when consumer repositories enable "Require review from
Code Owners" in a GitHub ruleset or branch protection; the file alone does not block a merge.

## 5. Public vs private consumer repos

- In **public** consumer repos, never commit real env files; run publish-safety before visibility changes.
- Skills contain synthetic vulnerable examples - still review diffs so labelled blocks are not copied live.
- This toolkit's own CI validates its Markdown; your application still needs its own gates.

## 6. Loading budget

Per task: at most five `core/`, two `advanced/`, one `enterprise/`, one `architecture/`
skill, with `depends_on` counting toward the cap. See
[skills/shared/references/skill-graph.md](../skills/shared/references/skill-graph.md).
