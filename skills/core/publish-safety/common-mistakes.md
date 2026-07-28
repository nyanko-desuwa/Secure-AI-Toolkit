# Common Mistakes

What goes wrong in practice, and why the fix works. The interesting cases are the ones where the
wrong version looks responsible — a `.gitignore` entry added, a commit deleted, a file renamed to
`.example`. Each of those reads as diligence in a diff.

## Adding the ignore rule after the file was already tracked

`A02:2025` · `CWE-527`

The rule appears in the diff, the reviewer approves it, and the file keeps being committed on every
push.

```bash
# Vulnerable: .env was tracked yesterday, so this rule governs nothing
echo ".env" >> .gitignore
git commit -am "chore: gitignore .env"
```

Why it survives review: the diff is exactly what a fix looks like. `git status` is clean afterwards
because the tracked file has no modifications, and nobody runs `git ls-files | grep env`.

```bash
# Fixed
git rm --cached .env
echo ".env" >> .gitignore
git commit -m "stop tracking .env"
git log --all --full-history --oneline -- .env   # then rotate everything this shows
```

Why the fix closes it: `.gitignore` is only consulted for untracked paths, so the file has to leave
the index before the rule means anything. The weaker fix people reach for is `git rm .env`, which
also deletes the working copy and breaks the local environment — so it gets reverted, and the
tracking comes back with it.

## Treating a history rewrite as the remediation

`A04:2025` · `CWE-798`

`git filter-repo` runs, the force-push succeeds, the string is gone from the log, and the ticket
gets closed.

```bash
# Vulnerable: this is cleanup presented as a fix
git filter-repo --path .env --invert-paths
git push --force
# → "removed the leaked key"
```

Why it survives review: the value genuinely is absent from what you can now see, which is the only
thing anyone checks. GitHub's own documentation is explicit that rewriting alone leaves the commits
reachable — in existing clones and forks, in cached views addressable by SHA, and through
`refs/pull/` refs that a force-push does not update (verified 2026-07-28).

```bash
# Fixed: order the response, and do the cleanup last if at all
# 1. Revoke at the provider — make the old value useless
# 2. Rotate — issue and deploy the replacement, with no overlap window
# 3. Investigate — read the provider audit log for the exposure window
# 4. Optional hygiene: rewrite history, knowing it changes nothing about the exposure
```

Why the fix closes it: revocation is the only step that acts on the copies you cannot reach. The
full ordered procedure, including what to check in the audit log and which leak locations need an
extra step, is in
[secrets-management/references/exposure-response.md](../secrets-management/references/exposure-response.md).

Also worth knowing before starting a rewrite: it changes every commit hash from that point on,
breaks signatures, permanently breaks diffs on closed pull requests, and can be undone by one
collaborator pushing from a stale clone.

## Reading a clean `git status` as a clean history

`A04:2025` · `CWE-527`

```bash
# Vulnerable: the pre-publish check, in full
git status      # clean
ls -la          # no .env in sight
```

Why it survives review: both commands answer honestly about the present. The question that matters
— "was anything sensitive ever committed" — was never asked, and there is no visible signal that it
was skipped.

```bash
# Fixed
git log --all --full-history --oneline \
  -- ".env" ".env.*" "*.pem" "*.key" "*.p12" "*credentials*.json"
gitleaks detect --source . --redact --log-opts="--all"
```

Why the fix closes it: `--all --full-history` reaches deleted branches and unreferenced ancestors,
which is precisely where a "removed" secret sits. The filename search and the pattern scan miss
different things, so run both.

## Assuming a private repository makes secrets safe

`A02:2025` · `CWE-540`

A committed credential is accepted because "the repo is private". Then the repo goes public, or
gets forked into a personal account, or a contractor is added, or a CI integration is granted read
access to the whole org.

Why it survives review: the reasoning is true on the day it is made. What changes is the audience,
and audience is a setting somebody else can flip in two clicks — at which point the entire history
publishes at once, not just today's files.

The fix is to treat "private" as a delay, not a control: no credential is committed regardless of
visibility, and every credential that was committed while private is rotated before the visibility
changes. Why this works: it removes the dependency on a setting that is outside the code's control.

## `.env.example` created by copying `.env`

`A04:2025` · `CWE-798`

```bash
# Vulnerable: copies the values along with the keys
cp .env .env.example
git add .env.example
```

Why it survives review: the filename says example, so a reviewer skims it. The diff shows a
committed template, which is the pattern everyone wants to see.

```bash
# Fixed
sed -E 's/=.*/=/' .env > .env.example
```

Why the fix closes it: the transformation cannot carry a value through. Read the output before
staging it anyway — `sed` does not understand a multi-line PEM block, so a private key spanning
several lines survives the strip.

## `npm publish` with no allowlist

`A03:2025` · `CWE-540`, `CWE-538`

```bash
# Vulnerable: no files field in package.json
npm publish
```

Everything in the directory that is not ignored goes into the tarball: `.env`, `scripts/`,
internal notes, test fixtures with real data. Verified against the npm docs on 2026-07-28 — with no
`files` field the default is `["*"]`.

Why it survives review: publishing succeeds and the package works when installed, so nothing signals
that extra files shipped. `npm unpublish` removes the listing while mirrors and lockfile caches keep
the tarball.

```json
// Fixed
{ "files": ["dist/", "README.md", "LICENSE"] }
```

Then `npm pack --dry-run` and read the file list. Why the fix closes it: the default flips from
include to exclude, so the failure mode becomes a missing file you notice immediately.

Note the precedence trap: a `.npmignore` at the package root does not override `files`, but one in
a subdirectory does override it there.

## `COPY . .` with no `.dockerignore`

`A02:2025` · `CWE-527`, `CWE-538`

```dockerfile
# Vulnerable
COPY . .
```

The build context is the whole directory. `.gitignore` has no bearing on it, so `.env` and the
entire `.git` directory — history included — land in a layer that anyone who pulls the image can
extract.

Why it survives review: the Dockerfile is short and idiomatic, the image builds, the application
runs. Nothing in the build output mentions what was copied.

```dockerfile
# Fixed
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src/ ./src/
```

Plus a `.dockerignore` with `.git`, `.env*`, and key patterns. Why the fix closes it: the narrow
`COPY` means a new stray file is not copied even if the ignore file misses it. `RUN rm .env` in a
later layer is not a fix — the earlier layer still holds the file.

## Mistaking a public env prefix for a private variable

`A04:2025` · `CWE-540`

`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_` — each tells the bundler to inline
the value into client JavaScript as a string literal.

Why it survives review: it is an environment variable in a gitignored `.env` file, which is where
secrets are supposed to live. The rule that catches it: if the value is needed by code running on
someone else's device, it is public, and no build setting changes that.

The fix is to move the call to a server route and keep the key server-side. Verify against the
build output rather than the source, because the source is where the value is *not* visible. The
per-framework table and the grep commands are in
[common-pitfalls/references/secret-exposure.md](../common-pitfalls/references/secret-exposure.md).

## A token in a screenshot, a pasted log, or a commit message

`A04:2025` · `CWE-532`, `CWE-615`

Nothing scans an image. Nothing scans a chat message. A terminal screenshot attached to an issue
carries whatever was in the scrollback, and an `Authorization` header pasted into a bug report is
readable by everyone on the thread.

Why it survives review: there is no diff, no commit, and no scanner output — so no review happens
at all. Editing the comment afterwards leaves the original in the edit history, in notification
emails already sent, and in any webhook that fired.

The fix is to redact before sharing, treat any pasted credential as exposed and rotate it, and
remember that AI prompts are a publish surface too: the provider logs the request, and there is no
purge path you control.

## Committing a local-only file because it sat in the repository root

`A02:2025` · `CWE-540`, `CWE-615`

Private notes, a personal instruction file, a scratch directory. `git add -A` sweeps it in, and the
first anyone knows is when a stranger reads it.

Why it survives review: blanket staging is the habit everyone has, and the file has been sitting
there harmlessly for weeks. Nothing distinguishes it from project content at `git add` time.

```bash
# Fixed: private exclusions stay private, and staging is explicit
cat >> .git/info/exclude <<'EOF'
my-notes.md
scratch/
EOF
git add src/api/invoices.py tests/test_invoices.py
```

Why the fix closes it: `.git/info/exclude` is per-clone and never committed, so a personal file
needs no entry in a shared `.gitignore`. Named-path staging turns the failure mode into "forgot a
file", which the next commit fixes.

## Quick table

| Mistake | Why it fails | Fix |
|---|---|---|
| `git push --force` after deleting the secret | The commit stays reachable by SHA, in forks, and in `refs/pull/` | Revoke, then rotate. Rewrite is hygiene |
| Unpublishing a package version | Mirrors and lockfile caches keep the tarball | Rotate anything it contained |
| Deleting a pushed image tag | The digest and every pulled copy remain | Rotate, rebuild without the layer |
| Renaming a repo instead of auditing it | Visibility and history are unchanged | Scan history before any visibility change |
| Redacting a value in a follow-up commit | The previous commit still has it | Treat as exposed, rotate |
| `.gitignore` as the only control | Nothing for tracked files, `git add -f`, or history | Add a hook, CI scanning, and push protection |
| Trusting a green scanner run | Scanners match patterns; a bare 32-char password matches none | Grep for the literal value of each key you own |

## Sources

- <https://owasp.org/Top10/2025/>
- <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository>
- <https://docs.npmjs.com/cli/v11/configuring-npm/package-json>
- <https://cwe.mitre.org/data/definitions/527.html>
- <https://cwe.mitre.org/data/definitions/540.html>
