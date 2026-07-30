---
name: publish-safety
description: 'Prove nothing sensitive ships before you push, publish, or make anything public. Covers git history, repository visibility, package and image registries, build output, and shared diffs. Triggers: "push to git", "make repo public", "npm publish", "docker push", "deploy", "leaked .env", "push lên git", "lộ .env".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Publish Safety

Publishing is a one-way door. On the far side, the only remediation is revocation at the
provider - not a commit, not a force-push, not a deleted repository. This skill is the gate you
run before the door, and it applies to every push, publish, deploy, and shared screenshot.

## When to Use

- Before the first `git push` of a project, or any push that adds files
- Before flipping a repository from private to public, or forking one out of an org
- Before `npm publish`, `pip upload`, `cargo publish`, `docker push`, or a release upload
- Before deploying build output to static hosting
- Before pasting a diff, a log, an error, or a screenshot into an issue, a chat, or a prompt
- After discovering something already shipped that should not have

## When NOT to Use

| Situation | Use instead |
|---|---|
| Deciding where a credential should live, or designing rotation | `secrets-management` |
| Responding to a confirmed leak beyond the first hour | `secrets-management`, `advanced/incident-response` |
| Configuring scanners as CI gates, or hardening a workflow | `devsecops` |
| Finding secrets inlined in a frontend bundle during development | `common-pitfalls` |
| Hardening the image itself: user, capabilities, base image | `docker-security` |
| Signing artifacts, provenance, SLSA | `advanced/supply-chain-security` |

This skill owns one moment: the transition from private to public. Everything before it
(where the secret lives) and after it (how to run the incident) belongs elsewhere.

## Standards This Skill Maps To

| Standard | Use it for | Version here |
|---|---|---|
| Top 10 2025 A02 Security Misconfiguration | The packaging and visibility settings that decide what ships | 2025 |
| Top 10 2025 A04 Cryptographic Failures | The credential itself, once exposed | 2025 |
| Top 10 2025 A03 Software Supply Chain Failures | What you publish becoming someone else's dependency | 2025 |
| ASVS 5.0 V13 Configuration | Verifying that config and code are separated | 5.0.0 |
| ASVS 5.0 V14 Data Protection | Verifying that sensitive data does not reach a public sink | 5.0.0 |
| CWE-527, CWE-540, CWE-538, CWE-798, CWE-615, CWE-532 | The specific weakness behind each finding | verified 2026-07-28 |

Details, with source URLs and check dates, in [references/](references/).

## One-Way Doors

What each action actually publishes, and what un-publishing does not undo.

| Action | Readable afterwards by | What reverting undoes |
|---|---|---|
| `git push` to a public repo | Anyone, plus code-search indexes and scanning bots within minutes | The tip. Not history, not forks, not clones, not PR refs |
| Private repo => public | Anyone, for the whole history, not just today's files | Visibility. Anything already cloned or indexed stays out |
| `npm publish` / `pip upload` | Anyone; the tarball is permanent even after unpublish/yank | The listing. Mirrors and lockfile caches keep the artifact |
| `docker push` | Anyone with pull access to the registry; every layer, including deleted files | The tag. The digest and pulled copies remain |
| Deploy build output | Every visitor, via view-source and the network tab | The next deploy. CDN caches and archives lag |
| Mobile store build | Anyone who downloads and unzips the package | Nothing until the next release ships and users update |
| PR diff, issue, screenshot, pasted log | Anyone reading the thread; edits leave the original in the event history | The visible text. Not the edit history, notification emails, or webhooks |
| Paste into an AI prompt | The model provider, per its retention policy | Nothing you control |

The pattern: reverting changes what a person sees when they look now. It does not change who
already has a copy. That is why the check belongs before the action.

## Workflow

### 1. Inventory what will ship

List the files the action will publish - not the files you edited. These are different sets, and
the gap is where leaks live.

```bash
git status --porcelain                       # staged and untracked, this push
git ls-files                                 # everything already tracked
npm pack --dry-run                           # exactly what the tarball will contain
docker build -t local:check . && docker history --no-trunc local:check
```

Then read the list. A file you did not write is still a file you are publishing.

### 2. Scan history, not just the worktree

`git status` describes the present tense. A credential committed in March and deleted in April is
still in every clone.

```bash
git log --all --full-history --oneline -- ".env" ".env.*" "*.pem" "*.key" "*.p12" "*credentials*.json"
```

Any output here means the value is in history and must be treated as exposed. This is the check
that a visibility flip turns from theoretical to urgent, because it exposes the whole history at
once. See [best-practices.md](best-practices.md#gate-a-visibility-change-on-a-full-history-scan).

### 3. Scan the built artifact

Build first. Bundlers inline environment variables, so a key can be absent from every file you
wrote and present in what you ship.

Per-stack commands and the public-prefix table are in
[common-pitfalls/references/secret-exposure.md](../common-pitfalls/references/secret-exposure.md) -
use those rather than reinventing the greps.

### 4. Check the packaging manifest

Allowlist, never denylist. An ignore file fails silently when someone adds a new directory; an
allowlist fails loudly. See [best-practices.md](best-practices.md#publish-by-allowlist).

Four ignore surfaces move together and are usually out of sync:
`.gitignore`, `.dockerignore`, `.npmignore` or `files`, and the host's ignore file.

### 5. Check the human channels

The diff, the issue, the screenshot, the pasted stack trace, the commit message, the AI prompt.
These bypass every scanner you installed, because nothing scans an image or a chat message.

Also check for local-only files: private notes, personal instruction files, scratch directories,
editor state. If it is not part of the project, it does not get staged. Keep it out with
`.git/info/exclude` or a global gitignore so a personal file does not need a rule in a shared
`.gitignore` - see [best-practices.md](best-practices.md#keep-local-only-files-out-without-a-shared-rule).

### 6. Verify and report

Run [checklist.md](checklist.md). Report what you checked, what you found, and what you could not
verify. If anything was found, stop - do not publish and then mention it.

For each finding, say the cost in plain words before the technical detail. "Your Stripe secret key
is in the published tarball, so anyone who downloads it can charge cards on your account" lands
where "credential present in package artifact" does not.

## Severity

Audience reach × credential scope. Where it was found matters less than who can read it.

- **Critical** - a live production credential with write or admin scope in a public place: public
  repo or its history, public registry artifact, deployed bundle, store build. Assume automated
  use within minutes.
- **High** - a live production credential in a place with broad internal read: private repo
  history, CI log, org-wide registry, a shared chat channel. Or any credential in a place you do
  not control, such as a model provider's logs.
- **Medium** - a scoped, short-lived, or non-production credential in a public place. Internal
  hostnames, infrastructure detail, or private paths published with no credential attached.
- **Low** - a missing ignore rule or allowlist with nothing sensitive currently in scope. A
  local-only file committed that contains nothing private.

Do not inflate, and do not deflate. A "read-only" key is not automatically medium - read access on
a customer database is a breach. A committed `.env` holding only `PORT=3000` is low.

## Related Skills

- `secrets-management` - where credentials should live, rotation, and the revoke/rotate/investigate
  order once something has leaked
- `common-pitfalls` - build-output greps, per-framework public env prefixes, keys that are meant to
  be public
- `devsecops` - pre-commit hooks and CI secret scanning as enforced gates, fork-PR exposure
- `docker-security` - image layers and build context beyond the secrets question
- `advanced/supply-chain-security` - signing and provenance for what you publish
- `advanced/incident-response` - the wider process when a leak becomes an incident

## Supporting Files

- [README.md](README.md) - purpose, configuration, limitations, security notes
- [checklist.md](checklist.md) - pre-publish verification, grouped by surface
- [best-practices.md](best-practices.md) - patterns with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when the guidance cannot be applied
- [prompts.md](prompts.md) - beginner, developer, review, and audit prompts
- [references/](references/) - Top 10, ASVS, CWE, and platform controls, version-pinned
- [examples/](examples/) - seven vulnerable/fixed pairs
