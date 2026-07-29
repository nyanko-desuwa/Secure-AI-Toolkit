# Platform Controls at the Publish Boundary

What each platform actually does, so a finding can say "push protection is off on this repository"
rather than "you should enable scanning". Every claim below was fetched from the vendor's own
documentation on 2026-07-28. Where a detail could not be confirmed, it says so instead of filling
the gap.

Platform behaviour changes more often than a standard does. Re-check before quoting a default.

## GitHub - secret scanning and push protection

Source: <https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection> ·
verified 2026-07-28

Push protection rejects the push at the server, before the object reaches the repository. It covers
command-line pushes, commits and file uploads made in the web UI, REST API requests, and GitHub MCP
server interactions (public repositories only for that last one).

Two distinct flavours, and confusing them produces a wrong finding:

| Flavour | Applies to | Default |
|---|---|---|
| Push protection for users | GitHub.com only; blocks pushing a secret to a public repository | Enabled by default, no cost |
| Push protection for a repository or organisation | Any visibility | Requires GitHub Secret Protection, and starts disabled until an admin, org owner, security manager, or enterprise owner turns it on |

So "GitHub will stop me" is true by default only for pushes to public repositories by a user. On a
private repository with Secret Protection not enabled, nothing blocks the push.

Bypass, and why it matters for a finding: on repository-level protection the default is that anyone
with write access can push through by choosing a reason. The reason chosen determines the resulting
alert state - "used in tests" and "false positive" close the alert, "I'll fix it later" leaves it
open. Bypasses generate an alert in the Security tab, an audit log entry, and email to owners,
security managers, and watching admins. Delegated bypass narrows who can do it. User-level bypasses
create no alert unless repository-level protection is also on.

What this means in practice: push protection is a strong control against accident and a weak one
against determination. Treat a bypassed push the same as an unprotected one - the value reached the
remote.

## GitHub - removing sensitive data after the fact

Source: <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository> ·
verified 2026-07-28

GitHub's own position, quoted because people argue with this one: if the exposed data is a
credential, "as a first step you need to revoke and/or rotate that secret", and once that is done,
"Going through the extra steps to rewrite the history and remove the secret may not be warranted."

Force-pushing does not finish the job. Per the same page, "If you only rewrite your history and
force push it, the commits with sensitive data may still be accessible elsewhere" - in clones and
forks, in cached views reachable by SHA-1, and through pull requests referencing the old commits.

What you cannot fix yourself:

- Other people's clones. "You cannot remove sensitive data from other users' clones of your
  repository." Collaborators must follow the `git-filter-repo` cleanup themselves, and must rebase
  rather than merge - a single merge commit reintroduces the purged history.
- Forks. "If the commit that introduced the sensitive data exists in any forks, it will continue to
  be accessible there." You have to ask the fork owners, and "GitHub cannot provide contact
  information for these owners."
- Caches and `refs/pull/` refs. A force-push does not update read-only pull request refs. Clearing
  them needs a GitHub Support ticket; Support then dereferences or deletes affected PRs, runs
  server-side garbage collection, removes cached views, and purges orphaned LFS objects.

And the catch on Support: "GitHub Support won't remove non-sensitive data," and they act on
sensitive data only where they judge that "the risk can't be mitigated by rotating affected
credentials." Rotation is not merely the recommended first step - it is effectively the gate on
getting help at all.

Costs of the rewrite, worth stating before anyone starts: every commit hash from the rewrite point
changes, hash-dependent automation breaks, commit and tag signatures are stripped, force-push
protections must be disabled, diff views on closed PRs break permanently, and there is a high risk
of recontamination when a collaborator with a stale clone pulls and pushes. The page also notes the
irony that visible history divergence points an observer straight at the data still sitting in their
local copy.

## GitLab - secret push protection

Source: <https://docs.gitlab.com/user/application_security/secret_detection/secret_push_protection/> ·
verified 2026-07-28

Blocks the push in the pre-receive hook. Since GitLab 17.11 it scans "only the diffs of commits
pushed over HTTP(S) and SSH". A match fails the push with a message naming the commit ID, file and
line, and secret type.

| Property | Value |
|---|---|
| Tier | Ultimate |
| Offering | GitLab.com, Self-Managed, Dedicated |
| Enabled by default | No. Opt-in per project |
| GA since | 17.5; last feature flag removed in 17.7 |

On Self-Managed and Dedicated an admin must first allow it instance-wide, then a project maintainer
enables the project toggle. Group-wide enablement is available through the group security settings
API.

Documented skip paths, both audited: `git push -o secret_push_protection.skip_all`, or
`[skip secret push protection]` in a commit message for clients that cannot send push options,
including the Web IDE. Audit events record the skip method, account, timestamp, project, target
branch, and the commits involved.

Cases where protection silently does not apply - each one a real gap to account for rather than a
footnote: configured exclusions, binary files, files or diff patches over 1 MiB, renames or moves
with no content change, duplicate file content, the initial repository push, and very large
changesets (documented as more than 3,150 changed paths or 350,000 lines, to prevent push timeouts).

Two of those deserve emphasis. The initial push is exactly the push most likely to carry a
historically committed `.env`. And a large import is exactly the changeset nobody reads. Pipeline
secret detection still scans contents after the push, so configure both layers if the tier allows.

## npm - what ends up in the tarball

Source: <https://docs.npmjs.com/cli/v11/configuring-npm/package-json#files> ·
verified 2026-07-28

`files` is an allowlist. Its patterns use ".gitignore, but reversed" semantics: listing a file,
directory, or glob pulls it in. Omit the field and it defaults to `["*"]` - everything ships.

Precedence, which is the part that produces surprises:

| Rule | Behaviour |
|---|---|
| `.npmignore` at the package root | Does not override the `files` field |
| `.npmignore` in a subdirectory | Does override `files` for that directory |
| `.gitignore` | Used only when no `.npmignore` exists |

So resolution is `.npmignore` first, `.gitignore` as a fallback. A project that relies on
`.gitignore` for packaging loses that protection the moment someone adds an `.npmignore` for an
unrelated reason.

Always included regardless of configuration: `package.json`, `README` and `LICENSE`/`LICENCE` in any
casing or extension, whatever `main` points to, and whatever `bin` points to.

Always excluded by default: `*.orig`, `.*.swp`, `.DS_Store`, `._*`, `.git`, `.hg`, `.lock-wscript`,
`.npmrc`, `.svn`, `.wafpickle-N`, `CVS`, `config.gypi`, `node_modules`, `npm-debug.log`,
`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lockb`.

Most of that set can be forced back in with a `files` glob. These cannot, whatever you write:
`.git`, `.npmrc`, `node_modules`, and the lockfiles. For a published lockfile the documented route
is `npm-shrinkwrap.json`.

Note what is not on the default-excluded list: `.env`, `.env.local`, `*.pem`, `*.key`. Nothing stops
those shipping unless an allowlist or an ignore rule excludes them. Verify with `npm pack --dry-run`
rather than reasoning about the rules.

## Docker - layers and history

`docker history --no-trunc <image>` prints the command that created each layer.
`docker image inspect --format '{{json .Config.Env}}'` prints the environment baked into the image.
Both were used in this repository's existing guidance and behave as described in
`core/common-pitfalls/references/secret-exposure.md`, which holds the extraction commands.

The property that matters: a file added in one layer and deleted in a later one is still present in
the earlier layer, and a `docker save` plus `tar -xf` recovers it. Layer deletion is not removal.
`ARG` and `ENV` values are readable by anyone who pulls the image.

Not verified here: registry-side scanning defaults for Docker Hub, GHCR, ECR, and their equivalents.
They differ per registry and per plan tier, so check the specific registry rather than assuming a
scan happened.

## What this file deliberately does not claim

- Whether a given repository has push protection on. Only the repository's settings page or API
  answers that, and neither is readable from source.
- Whether a credential was actually used during an exposure window. That is the provider's audit
  log.
- Retention policies for AI model providers. They vary by vendor, plan, and enterprise agreement.
  Assume retention and rotate; do not quote a specific window.

## Sources

- GitHub push protection - <https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection>
- GitHub, removing sensitive data - <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository>
- GitLab secret push protection - <https://docs.gitlab.com/user/application_security/secret_detection/secret_push_protection/>
- npm `files` and ignore precedence - <https://docs.npmjs.com/cli/v11/configuring-npm/package-json#files>
