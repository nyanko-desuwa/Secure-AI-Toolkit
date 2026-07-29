# Publish Safety Examples

Seven pairs. Each one is a thing that gets published by accident, next to the version that does
not. Category, CWE, and ASVS chapter on every entry.

Read these as patterns. The command syntax is incidental; the wrong assumption is the subject.

## Contents

- [Ignore rule added after the file was tracked](#ignore-rule-added-after-the-file-was-tracked) - A02, CWE-527
- [Visibility flipped with no history scan](#visibility-flipped-with-no-history-scan) - A04, CWE-527
- [History rewrite presented as the fix](#history-rewrite-presented-as-the-fix) - A04, CWE-798
- [`npm publish` with no allowlist](#npm-publish-with-no-allowlist) - A03, CWE-538
- [`.env.example` copied instead of stripped](#envexample-copied-instead-of-stripped) - A04, CWE-798
- [`COPY . .` into an image](#copy---into-an-image) - A02, CWE-538
- [Build output with an inlined key deployed to static hosting](#build-output-with-an-inlined-key-deployed-to-static-hosting) - A04, CWE-540

---

## Ignore rule added after the file was tracked

`A02:2025` · `CWE-527` · ASVS V13

The most common version of this bug, because the fix looks like it worked. `git status` goes
quiet, so the file appears handled.

```bash
# Vulnerable: assumes .gitignore applies to a file git is already tracking
git add .env                 # last week, by accident
git commit -m "wip"          # .env is now tracked
echo ".env" >> .gitignore    # today, believing this fixes it
git status                   # clean. The file is still tracked and still shipping.
```

Every future commit continues to include changes to `.env`, and the value already in history is
in every clone. On the next push to a public repository, scanning bots read it within minutes.

```bash
# Fixed: untrack first, then ignore, then treat the old value as exposed
git rm --cached .env
printf '.env\n.env.*\n!.env.example\n' >> .gitignore
git commit -m "untrack .env"

# Confirm it is gone from the index, and find out how far back it goes
git ls-files --error-unmatch .env      # expect: "did not match any file"
git log --all --full-history -- .env
```

Why this works: `.gitignore` is consulted only for untracked paths. `git rm --cached` removes the
path from the index while leaving your local file alone, which is what moves it into the set the
ignore rule can actually govern.

Remaining gap, and it is the important half: the commit that added the file is still in history.
Untracking stops the bleeding, it does not undo the exposure. Rotate every credential that was in
that file - see
[secrets-management/references/exposure-response.md](../../secrets-management/references/exposure-response.md).

---

## Visibility flipped with no history scan

`A04:2025` · `CWE-527` · ASVS V14

A private repository is not a vault; it is a repository with fewer readers. Flipping it public
publishes ten months of history at once, not today's files.

```bash
# Vulnerable: the working tree is clean, so the repo is assumed clean
git status                     # nothing to commit
# → flip to public in the repository settings
```

The current tree has no secrets. The `config.py` from March, deleted in April, has the database
password. It is reachable by SHA the moment the repository is public, and code-search indexes
scrape new public repositories continuously.

```bash
# Fixed: scan all of history, on every branch, before the switch
git log --all --full-history --oneline -- \
  ".env" ".env.*" "*.pem" "*.key" "*.p12" "*credentials*.json" "*secrets*"

# Content, not just filenames - a key pasted into a source file has no telltale name
gitleaks detect --source . --log-opts="--all" --redact
```

Why this works: `--all` covers refs you no longer have checked out and `--full-history` keeps
commits that simplification would otherwise drop. A content scan catches the case a filename
scan cannot: a credential pasted inline into a file that is supposed to be there.

The tempting wrong order is flip-then-scan, on the reasoning that you can always flip back.
Visibility is reversible; the fork, the clone, and the index that happened in between are not.

---

## History rewrite presented as the fix

`A04:2025` · `CWE-798` · ASVS V14

The reflex, and the one that costs the most time while fixing the least.

```bash
# Vulnerable: treats making the value invisible as making it useless
git filter-repo --path .env --invert-paths
git push --force
# → report "secret removed"
```

The key still authenticates. GitHub's own guidance is that a rewrite plus force-push leaves the
commits reachable in clones, in forks, and through cached views addressed by SHA - and that
Support only assists when the risk cannot be handled by rotating the credential. Meanwhile every
collaborator with a stale clone can push the data straight back.

```bash
# Fixed: revoke at the provider first. The rewrite is optional cleanup afterwards.

# 1. Revoke - make the old value fail authentication
aws iam update-access-key --access-key-id AKIAEXAMPLEPLACEHOLDER --status Inactive
aws iam delete-access-key --access-key-id AKIAEXAMPLEPLACEHOLDER

# 2. Rotate - issue and deploy the replacement, no overlap window
# 3. Investigate - read the provider audit log for the exposure window
# 4. Only now, and only for hygiene:
#    git filter-repo ... ; notify collaborators to re-clone, not merge
```

Why this works: revocation acts on the system that honours the credential, so it holds regardless
of how many copies exist. Nothing else has that property.

State this in the report explicitly. A rewrite described as remediation closes the ticket while
the credential is still live, which is the worst outcome available.

---

## `npm publish` with no allowlist

`A03:2025` · `CWE-538` · ASVS V13

Publishing defaults to including everything. The tarball contains what you forgot, not what you
listed.

```json
// Vulnerable: no files field, so the default is ["*"]
{
  "name": "@acme/widget",
  "version": "1.4.0",
  "main": "dist/index.js"
}
```

`.env.local`, `scripts/deploy.sh` with an inline token, `notes.md`, and `.vscode/` all ship.
Unpublishing removes the listing, not the tarball from mirrors and lockfile caches.

```json
// Fixed: allowlist what ships
{
  "name": "@acme/widget",
  "version": "1.4.0",
  "main": "dist/index.js",
  "files": ["dist", "!dist/**/*.map"]
}
```

```bash
# Verify against the actual tarball, not the config
npm pack --dry-run
```

Why this works: an allowlist fails closed. A new directory added next month is absent from the
package until someone lists it, whereas a denylist silently includes it.

Two npm specifics worth knowing, from the npm `package.json` documentation: a root `.npmignore`
does not override `files`, but a `.npmignore` in a subdirectory does; and `.gitignore` is used
only when no `.npmignore` exists. Do not reason about the tarball from your `.gitignore`.

---

## `.env.example` copied instead of stripped

`A04:2025` · `CWE-798` · ASVS V13

The template file is committed on purpose, which is exactly why nobody scans it.

```bash
# Vulnerable: copies the values along with the keys
cp .env .env.example
git add .env.example
```

```text
# .env.example, as committed
DATABASE_URL=postgres://appuser:hunter2-real-password@db.internal:5432/prod
STRIPE_SECRET_KEY=sk_live_PLACEHOLDER_BUT_THIS_LINE_WAS_REAL
```

Reviewers skim past a file whose whole purpose is to be committed. The keys are the point of the
file, so the values do not look out of place.

```bash
# Fixed: generate it from the keys, discard the values
sed -E 's/=.*/=/' .env | sort -u > .env.example
git add .env.example
```

```text
# .env.example, generated
DATABASE_URL=
STRIPE_SECRET_KEY=
```

Why this works: the value never enters the file, so there is nothing to remember to remove. A
review step that depends on someone noticing is a review step that fails eventually.

Add the negation to the ignore file so the template survives a broad rule:

```gitignore
.env
.env.*
!.env.example
```

---

## `COPY . .` into an image

`A02:2025` · `CWE-538` · ASVS V13

Layers are additive. Deleting a file in a later instruction leaves it in the earlier layer, and
`docker history` shows what put it there.

```dockerfile
# Vulnerable: the build context includes .env, .git, and every local file
FROM node:22-alpine
WORKDIR /app
COPY . .
RUN rm -f .env          # too late - the previous layer still has it
RUN npm ci --omit=dev
CMD ["node", "dist/index.js"]
```

Anyone who can pull the image extracts the layer and reads `.env`. `.git` ships too, which hands
over the full history along with it.

```dockerfile
# Fixed: copy only what the build needs, in dependency order
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY tsconfig.json ./
RUN npm run build
CMD ["node", "dist/index.js"]
```

```dockerignore
# .dockerignore - belt as well as braces
.git
.env
.env.*
!.env.example
node_modules
*.pem
*.key
```

```bash
# Verify the built image, not the Dockerfile
docker history --no-trunc local:check
docker save local:check -o /tmp/img.tar && tar -xf /tmp/img.tar -C /tmp/img
grep -rEl "BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}" /tmp/img
```

Why this works: naming the paths means an unexpected file in the working directory cannot enter
the image at all. `.dockerignore` is the second layer, and it also stops the context upload - but
the explicit `COPY` is what makes the guarantee.

For a build-time credential that genuinely cannot be avoided, use
`RUN --mount=type=secret`, which never lands in a layer. Never `ARG` - build args are visible in
image metadata.

---

## Build output with an inlined key deployed to static hosting

`A04:2025` · `CWE-540` · ASVS V14

The source is clean. The bundle is not. Bundlers replace public-prefixed variables with string
literals at build time.

```javascript
// Vulnerable: a server-scoped key read in code that ships to the browser
// app/lib/mail.ts, imported by a client component
const key = process.env.NEXT_PUBLIC_SENDGRID_API_KEY;

export async function sendWelcome(to: string) {
  await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}` },
    body: JSON.stringify({ to }),
  });
}
```

The key is a literal in a file under `.next/static/`. Any visitor opens devtools and sends mail
from your account. `grep` over `app/` finds only the variable name, which is why source-only
review passes this.

```javascript
// Fixed: the credential stays server-side; the browser calls your route
// app/api/welcome/route.ts  - server only
export async function POST(req: Request) {
  const { to } = await req.json();
  await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.SENDGRID_API_KEY}` },
    body: JSON.stringify({ to }),
  });
  return Response.json({ ok: true });
}
```

```bash
# Verify the artifact, after building
npm run build
grep -rn "SG.PASTE-THE-ACTUAL-KEY-VALUE-HERE" .next/static/ dist/ build/ 2>/dev/null
grep -rEn "NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_" src/ app/
```

Why this works: the credential is only ever read in a process on hardware you control. Renaming
the variable to drop the prefix is not sufficient on its own - the bundler follows imports, so a
non-prefixed value imported into a client component still ships.

Per-framework prefixes, the keys that are meant to be public, and the full grep set are in
[common-pitfalls/references/secret-exposure.md](../../common-pitfalls/references/secret-exposure.md).

---

## Safety

Every vulnerable block above is labelled `Vulnerable:` on its first line and paired with a fix.
Do not copy a labelled-vulnerable block into a project.

All values are placeholders. `AKIAEXAMPLEPLACEHOLDER`, `hunter2-real-password`, and the
`PLACEHOLDER` key strings are not live credentials, and `db.internal` is not a real host.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- npm `package.json` `files` and `.npmignore` - <https://docs.npmjs.com/cli/v11/configuring-npm/package-json>
- GitHub, removing sensitive data from a repository - <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository>
- CWE-527, CWE-538, CWE-540, CWE-798 - <https://cwe.mitre.org/>
