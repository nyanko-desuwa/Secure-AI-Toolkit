# Publish Safety Best Practices

Patterns that hold up under review. Each one names the standard it serves, so a finding can be
traced back.

The theme running through all of them: make the unsafe outcome structurally unreachable rather
than asking someone to remember. A rule that depends on discipline fails on the busy Tuesday.

## Publish by allowlist

`A02:2025` · ASVS V13 (Configuration) · `CWE-527`, `CWE-538`

An ignore file is a denylist. It covers what you thought of when you wrote it and fails silently
the day someone adds a directory. An allowlist fails the other way: forget to list a file and it
is missing from the package, which you notice immediately.

```json
// Vulnerable: no files field, so the tarball defaults to everything not ignored
{
  "name": "acme-sdk",
  "version": "2.1.0",
  "main": "dist/index.js"
}
```

Publish that with a `.env`, a `scripts/deploy.sh`, or a `notes/` directory in the tree and all of
it ships. `npm unpublish` removes the listing; the tarball stays in mirrors and lockfile caches.

```json
// Fixed: an explicit allowlist. Anything not listed cannot ship
{
  "name": "acme-sdk",
  "version": "2.1.0",
  "main": "dist/index.js",
  "files": ["dist/", "README.md", "LICENSE"]
}
```

Why this works: the default flips from include to exclude. A new top-level directory is out until
someone deliberately adds it, so the failure mode is a missing file rather than a published
secret.

Verified against the npm `package.json` documentation on 2026-07-28: `files` is an allowlist and
defaults to `["*"]` when absent. A root-level `.npmignore` does *not* override `files`, but one in
a subdirectory does override it there. `.gitignore` is used only when no `.npmignore` exists.
`package.json`, `README`, `LICENSE`, and the `main`/`bin` targets always ship regardless. See
[references/platform-controls.md](references/platform-controls.md).

Rules that follow:

- `npm pack --dry-run` before every publish, and read the file list rather than the count
- Python: `MANIFEST.in` plus `include_package_data`, and check the built sdist with `tar -tzf`
- Never rely on `.npmignore` alone when `files` is available

## Keep the four ignore surfaces in sync

`A02:2025` · ASVS V13 · `CWE-527`

`.gitignore` protects the repository. It does nothing for the Docker build context, the npm
tarball, or the static-host upload - each of those reads a different file, and they drift apart
the moment one is edited alone.

```dockerfile
# Vulnerable: the build context is the whole directory, including .env and .git
FROM node:22-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
```

`.gitignore` is irrelevant here. `COPY . .` copies `.env` and the entire `.git` directory -
history included - into a layer. `docker history` shows the instruction, and anyone who pulls the
image can extract the layer.

```dockerfile
# Fixed: narrow the copy, and exclude the context as a second layer of defence
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src/ ./src/
```

```gitignore
# .dockerignore - the build context, not the repository
.git
.env
.env.*
!.env.example
node_modules
*.pem
*.key
.claude/
```

Why this works: two independent mechanisms with different failure modes. The narrow `COPY` means
a new stray file is not copied even if `.dockerignore` misses it; `.dockerignore` means a widened
`COPY` in six months does not immediately leak.

A deletion in a later layer does not help. `RUN rm .env` leaves the file in the earlier layer,
still extractable.

Rules that follow:

- Every repository with a Dockerfile has a `.dockerignore` containing at least `.git` and `.env*`
- Prefer copying named paths over `COPY . .`
- Confirm with `docker history --no-trunc` and a layer extraction, not by reading the Dockerfile

## Gate a visibility change on a full-history scan

`A04:2025` · ASVS V14 (Data Protection) · `CWE-527`, `CWE-798`

Flipping a repository to public publishes the entire history at once, not the current file list.
Nobody reviews ten months of commits by eye, so the scan is the gate.

```bash
# Vulnerable: the pre-publish check people actually run
git status          # clean
ls -la              # no .env
# → make public
```

Both commands describe the present tense. A key committed in March and deleted in April is
invisible to both and present in every clone made from the repository.

```bash
# Fixed: ask history, then scan history
git log --all --full-history --oneline \
  -- ".env" ".env.*" "*.pem" "*.key" "*.p12" "*credentials*.json" "*secret*"

# Then a real scanner over the full history, not just the tip
gitleaks detect --source . --redact --log-opts="--all"
```

Why this works: `--all --full-history` reaches commits on deleted branches and unreferenced
ancestors, which is where a "removed" secret lives. A scanner catches patterned values a filename
search misses.

Order matters when there is a hit: revoke at the provider first, then rotate, then investigate.
Cleaning history is not remediation - see
[secrets-management/references/exposure-response.md](../secrets-management/references/exposure-response.md).

Rules that follow:

- Any hit blocks the visibility change until every value found has been rotated
- Enable provider-side push protection so the next one is blocked at the pre-receive hook
- Treat the scan as necessary and not sufficient: scanners match patterns, and a bare
  32-character database password matches nothing

## Untrack before you ignore

`A02:2025` · ASVS V13 · `CWE-527`

`.gitignore` only governs files git is not already tracking. Adding a rule for a tracked file
changes nothing, and the rule's presence is exactly what makes people stop checking.

```bash
# Vulnerable: the rule is added, the file keeps being committed
echo ".env" >> .gitignore
git commit -am "gitignore .env"
```

`.env` was tracked before the rule existed, so git continues to track it. `git status` shows
nothing unusual, which is why this survives.

```bash
# Fixed: stop tracking it, then ignore it, then treat the value as exposed
git rm --cached .env
echo ".env" >> .gitignore
git commit -m "stop tracking .env"

# The value is still in history. Rotate it.
git log --all --full-history --oneline -- .env
```

Why this works: `git rm --cached` removes the file from the index while leaving it on disk, so the
next commit records the deletion and the ignore rule takes effect from then on. The tempting
alternative - `git rm .env` - deletes the local file too and breaks the developer's environment,
which is how the change gets reverted.

Neither command touches history. If the file was ever pushed, rotation is the fix and the untrack
is hygiene.

## Generate `.env.example` by stripping, never by copying

`A04:2025` · ASVS V13, V14 · `CWE-798`

`cp .env .env.example` is one keystroke from `git add .env.example` with live values in it, and it
reads as a safe, responsible commit.

```bash
# Vulnerable: values come along for the ride
cp .env .env.example
git add .env.example
```

```bash
# Fixed: keep the keys, drop the values
sed -E 's/=.*/=/' .env > .env.example
git add .env.example
```

```gitignore
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*-credentials.json
```

Why this works: the transformation cannot preserve a value, so there is nothing to remember. The
`!.env.example` negation is what lets the broad `.env.*` rule coexist with the one file that
should be committed - without it, the example is ignored and new contributors get no key list.

Rules that follow:

- Read the generated file before staging it. `sed` does not know about a multi-line PEM block
- Every key the application requires appears in the example, so a missing variable is a startup
  error rather than a silent default
- Placeholders are obviously fake: `sk-REPLACE-ME`, not a real-shaped string

## Keep local-only files out without a shared rule

`A02:2025` · ASVS V13 · `CWE-527`, `CWE-540`

Private notes, personal AI instruction files, scratch directories, and editor state are not part
of the project. Adding each one to the shared `.gitignore` publishes the fact that it exists and
grows a file that other contributors have to reason about.

```bash
# Vulnerable: everything in the directory becomes tracked
git add -A
git commit -m "wip"
```

`git add -A` and `git add .` stage whatever is present, including a file created five minutes ago
that nobody has decided about yet. This is the single most common way a local-only file becomes a
public one.

```bash
# Fixed: private exclusions stay private, and staging is explicit
cat >> .git/info/exclude <<'EOF'
my-notes.md
scratch/
EOF

git add src/api/invoices.py tests/test_invoices.py
git commit -m "add invoice export endpoint"
```

Why this works: `.git/info/exclude` is per-clone and never committed, so a personal file needs no
entry in a shared file. Naming paths at `git add` time means an unreviewed file cannot be swept
in - the failure mode becomes "forgot to stage a file", which the next commit fixes.

A global gitignore covers patterns you carry between projects:

```bash
git config --global core.excludesFile ~/.gitignore_global
```

Rules that follow:

- Never `git add -A` or `git add .` on a repository that will be published
- A local-only file is never quoted in a commit message, a PR description, or a file that will be
  committed. If committed guidance needs to reference instructions, it references the committed
  entry point
- `git diff --cached --stat` before every commit, and read it

## Two scanning layers, different failure modes

`A02:2025` · `A03:2025` · ASVS V13, V15

A pre-commit hook blocks the write. It is bypassable with `--no-verify`, absent on a fresh clone,
and does not exist for a web edit. Server-side scanning catches those and runs after the push,
which means it is detection, not prevention. Both, or neither works.

Do not write new configurations for this. Two already exist in the toolkit, pinned and verified:

- [devsecops/examples/pre-commit-config.yaml](../devsecops/examples/pre-commit-config.yaml) -
  gitleaks and `detect-private-key` on the staged diff
- The `secret-scan.yml` workflow in
  [secrets-management/best-practices.md](../secrets-management/best-practices.md#detection) -
  gitleaks in CI with `fetch-depth: 0` so history is scanned, not just the tip

The third layer is provider-side and the only one an attacker's clone cannot skip: GitHub secret
push protection rejects the push at the pre-receive hook, GitLab's equivalent does the same on
Ultimate. Details, including what each one does not cover, in
[references/platform-controls.md](references/platform-controls.md).

Why the combination works: three mechanisms that fail differently. The hook is fast and
bypassable, CI is thorough and late, push protection is server-side and pattern-limited. A red CI
run is the signal to start the exposure response, not proof that you were protected.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- <https://docs.npmjs.com/cli/v11/configuring-npm/package-json>
- <https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection>
- <https://cwe.mitre.org/data/definitions/527.html>
