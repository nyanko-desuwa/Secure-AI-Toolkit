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
- A fix that closes the path, not only “looks safer”
- Explicit list of skills consulted and checks **not** run

## 2. Starter packs (install only what you need)

Claude Code discovers flat skill directories. Prefer 3–5 skills over all of them
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
| **Continue / Cline / Roo Code / Kiro** | Rules or context docs → `AI_INSTRUCTIONS.md` | Copy or link skill trees as the tool allows |

“Point the tool at `AI_INSTRUCTIONS.md`” always means: make that file part of the
model’s standing instructions, then load individual `skills/**/SKILL.md` files
when the task matches the routing table — do not paste the entire repository.

## 4. Team rollout

1. **Pin a release tag** (`vX.Y.Z`) rather than floating `main` if you need reproducibility.
2. Choose **project-scoped** install (`.claude/skills/…` committed) for shared baselines;
   personal install for experimentation.
3. Start with the starter pack for your system type; add skills when reviews repeatedly
   hit an adjacent boundary.
4. Require the output contract in PR templates (category, location, exploit path, fix).
5. Keep **owners** for standards re-pins (see [MAINTENANCE.md](../MAINTENANCE.md)).

### Complementary controls (not replaced by this pack)

| Control | Why |
|---|---|
| SAST | Cross-file taint and injection the model will miss |
| SCA / lockfile audit | Dependency risk (A03) |
| Secret scanning (history-aware) | Publish boundary |
| DAST / authz matrix tests | Runtime and BOLA evidence |
| IaC + container scan | Cloud/K8s/Docker reality |

## 5. Public vs private consumer repos

- In **public** consumer repos, never commit real env files; run publish-safety before visibility changes.
- Skills contain synthetic vulnerable examples — still review diffs so labelled blocks are not copied live.
- This toolkit’s own CI validates its Markdown; your application still needs its own gates.

## 6. Loading budget

Per task: at most five `core/`, two `advanced/`, one `enterprise/`, one `architecture/`
skill, with `depends_on` counting toward the cap. See
[skills/shared/references/skill-graph.md](../skills/shared/references/skill-graph.md).
