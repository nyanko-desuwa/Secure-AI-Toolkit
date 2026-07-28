# Pre-Publish Verification Checklist

Run this before the push, the publish, the deploy, or the paste — not after. Mark each item pass,
fail, or not applicable. "Not applicable" needs a one-line reason; an unexplained skip reads
exactly like an oversight.

Only run the sections matching the action. A package release does not need the container section.

Any fail stops the action. Report it, then wait.

## Before any push (A02 · A04 · ASVS V13 · CWE-798, CWE-540)

- [ ] Staged the change by named path. No `git add -A`, no `git add .`, no `git add -u`
- [ ] Read `git diff --cached --stat` and can account for every file in it
- [ ] No `.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, `*.p12`, `*credentials*.json`
      in the staged set
- [ ] `git status --porcelain` shows no untracked file that would be swept in by a blanket add
- [ ] No local-only file staged: private notes, personal AI instruction files, scratch
      directories, editor state, `.claude/local/`
- [ ] Commit message quotes no credential, no internal hostname, and no private file path
- [ ] `.gitignore` covers the ignore set, with `!.env.example` after the `.env*` rule
- [ ] Every file the ignore rules are meant to cover is actually untracked —
      `git ls-files | grep -E "^\.env|\.pem$|\.key$"` returns nothing. `.gitignore` does not
      affect an already-tracked file

## Before flipping a repository public (A02 · A04 · ASVS V13, V14 · CWE-527, CWE-540)

- [ ] Full-history scan run, not a worktree scan:
      `git log --all --full-history --oneline -- ".env*" "*.pem" "*.key" "*credentials*.json"`
- [ ] Secret scanner run over full history with `--redact`, not just over the tip
- [ ] Every hit rotated at the provider. Rotation done, not planned
- [ ] Branches, tags, and stashes considered — `--all` covers refs, `git stash list` does not
- [ ] Issues, PR descriptions, and PR comments reviewed. Those become public with the repo
- [ ] Wiki, releases, and attached release assets reviewed
- [ ] CI logs and build artifacts reviewed for values printed before masking existed
- [ ] Internal hostnames, IP ranges, ticket URLs, and customer names in code and commit messages
      assessed as intentional or removed
- [ ] Provider push protection enabled going forward, so the next one is blocked pre-receive

## Before `npm publish` / `pip upload` (A03 · ASVS V13 · CWE-538)

- [ ] `npm pack --dry-run` output read file by file, or `python -m build` plus
      `tar -tzf dist/*.tar.gz`
- [ ] `files` allowlist present in `package.json`, or `MANIFEST.in` plus
      `include_package_data`. Not relying on an ignore file alone
- [ ] Understood that a root `.npmignore` does not override `files`, and that `.gitignore` is only
      used when no `.npmignore` exists
- [ ] `package.json` itself carries no token: no `publishConfig` auth, no script with a credential
- [ ] No `.npmrc` with an auth token in the package directory
- [ ] Test fixtures, seed data, and `__tests__` excluded unless deliberately shipped
- [ ] Source maps checked: they can embed original source and inlined values
- [ ] Version number is new. Republishing over a tag is not possible on either registry

## Before `docker push` (A02 · A03 · ASVS V13 · CWE-538)

- [ ] `.dockerignore` exists and excludes `.env`, `.git`, `node_modules`, key files
- [ ] No `COPY . .` without a `.dockerignore` covering the build context
- [ ] `docker history --no-trunc <image>` shows no credential in any layer command
- [ ] No secret in `ARG` — build args are visible in image metadata
- [ ] No secret in `ENV` in the Dockerfile
- [ ] A file added in one layer and deleted in a later one is understood to still be present
- [ ] Image inspected as a filesystem, not just by history:
      `docker save <image> -o img.tar && tar -xf img.tar -C /tmp/img && grep -rl "PATTERN" /tmp/img`
- [ ] Registry visibility confirmed. A "private" registry with org-wide pull is broad internal read

## Before deploying build output (A04 · ASVS V14 · CWE-540)

- [ ] Built first, then searched the output. Source-only search misses inlined env vars
- [ ] Grepped the literal value of every key you own against `dist/`, `build/`, `.next/static/`,
      `out/`. Pattern matching alone misses keys with no recognisable prefix
- [ ] Every public-prefixed variable (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`,
      `PUBLIC_`) reviewed by value, and each is one a stranger may hold
- [ ] Keys that are designed to be public are distinguished from keys that are not, and the
      control that actually protects them is in place — RLS, security rules, referrer restriction
- [ ] Source maps either not deployed, or confirmed to contain nothing sensitive
- [ ] No `.env`, `.git`, or config file in the deployed directory
- [ ] Host ignore file (`.vercelignore`, `netlify.toml` publish path) matches intent

## Before sharing a diff, log, or screenshot (A09 · ASVS V14, V16 · CWE-532, CWE-615)

- [ ] Diff read line by line for tokens, connection strings, and internal URLs
- [ ] Pasted log or stack trace checked for `Authorization` headers, query-string tokens, and
      serialized config objects
- [ ] Screenshot checked for a terminal scrollback, a browser devtools panel, an editor tab, or a
      `.env` visible behind the window
- [ ] Understood that editing a comment leaves the original in the edit history and in the
      notification email already sent
- [ ] Anything pasted into an AI prompt treated as disclosed to the provider and rotated if it was
      a credential
- [ ] Code comments in the shared diff carry no stale credential or private link

## After something has already shipped (A04 · ASVS V14 · CWE-798)

- [ ] Revoked at the provider first. Not deleted from the file, not force-pushed
- [ ] Rotated, with a zero-length overlap window — the leaked value must not stay accepted
- [ ] Provider audit log read for the window between first exposure and revocation, where first
      exposure is the commit or push timestamp, not the moment you noticed
- [ ] Durable artifacts the credential could have created checked: new keys, new grants, new
      webhooks, scheduled jobs
- [ ] Exposure surface established: public repo, public registry, deployed bundle, third-party log
- [ ] History rewrite, if done at all, done after revocation and reported as hygiene rather than
      as the fix
- [ ] A control added so the same path cannot recur — pre-commit hook, CI scan, push protection,
      or removing the stored value entirely

## Before Returning

- [ ] Named which sections ran and which were not applicable, with reasons
- [ ] Every finding stated in plain language first: what leaked, who could read it, what it costs
- [ ] Nothing reported as verified that was not actually run
- [ ] Runtime and provider-side facts named as unverifiable from the repository: actual repository
      visibility, whether a value was truly revoked, what forks and mirrors hold
- [ ] Documentation updated where the change warrants it: skill `README.md`, root `README.md`,
      `CHANGELOG.md`
