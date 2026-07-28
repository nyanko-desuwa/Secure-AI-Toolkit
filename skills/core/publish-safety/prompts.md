# Prompt Examples

Prompts that produce findings instead of reassurance. Four tiers: beginner, developer, review, and
audit. They differ in what the reader is assumed to be able to check afterwards, not in how strict
they are.

Under each, one or two lines on why the phrasing works — that reasoning is what you adapt, not the
wording.

## Beginner

For someone who does not read code and needs to know whether it is safe to publish.

```
I am about to push this project to a public GitHub repo. Before I do, check whether anything
private would become visible: keys, passwords, .env files, personal notes, internal URLs.
Check the git history too, not just the current files. Tell me in plain language what you
found, what it would cost me if I pushed it, and what to do first.
```

Why it works: it names the action, asks for history rather than the working tree, and asks for the
cost in plain language. "Your OpenAI key is in the history, so anyone could spend your credits"
lands where "credential present in commit `a3f9c1`" does not.

```
This repo is private right now and I want to make it public. Is there anything in the whole
history that would leak? If yes, do not tell me how to delete the commit — tell me which keys I
need to change at the provider and in what order.
```

The second sentence pre-empts the wrong fix. Deleting a commit is the reflex; revoking is the
remediation.

## Developer

For someone writing the code and configuring the publish path.

```
Set up the publish boundary for this project. Create or fix .gitignore, .dockerignore, and the
files allowlist in package.json. Generate .env.example from .env by keeping the keys and
stripping every value. Then show me exactly what npm pack --dry-run and git status --porcelain
would publish, and tell me what you added to each file.
```

Asking for the resulting file list, not just the config, is what catches an ignore rule that does
not match. Asking what was added makes the change reviewable.

```
This project has a .env that was committed six months ago. Walk me through untracking it,
keeping it on disk, and fixing the ignore rules — then tell me plainly what that does and does
not solve, and which credentials need rotating regardless.
```

The "does not solve" clause is the point. `git rm --cached` fixes the future and nothing about
history.

```
I am adding a build step that deploys dist/ to static hosting. Which environment variables in
this project would end up inlined in the bundle? Check the public prefixes for this framework
specifically, then grep the built output for the literal value of each key.
```

Naming the framework gets the right prefix table. Asking for the literal-value grep catches keys
with no recognisable shape, which pattern matching misses.

## Review

For checking a change someone else — or an assistant — already made.

```
Review the staged diff for anything that should not be published. For each finding give the
file:line, the Top 10 2025 category and CWE, who would be able to read it after the push, and
the fix. Quote the actual line. Skip anything with no exploitation path and say you skipped it.
```

Asking who can read it afterwards is what makes severity honest here — audience reach is the
variable, not the category name.

```
Check whether the four ignore surfaces in this repo agree: .gitignore, .dockerignore, the npm
files field, and the host's ignore file. For each pattern that appears in one and not the others,
tell me whether that gap publishes anything and to where.
```

The gaps between ignore files are where leaks live, and no single-file review finds them.

```
We are about to publish v2.0 to npm. Run npm pack --dry-run and go through the contents line by
line. For each file, say why it is in the tarball and whether it needs to be. Flag anything that
is source, config, test fixture, or local tooling.
```

Line-by-line prevents the summary answer. A tarball with 400 files gets a verdict; a tarball read
line by line gets findings.

## Audit

For a full pass over a project or a repository's history, where the output is a report.

```
Audit this repository's publish boundary end to end. Cover: git history for credential files,
the current tracked file set, the built artifact, the package manifest, the container image
layers, and the commit messages. Use skills/core/publish-safety/checklist.md. For each section
report pass, fail, or not applicable with the command you ran and its output. List separately
what you could not verify from the repo alone.
```

Requiring the command and its output per section is what stops a wall of checkmarks. The last
sentence is what surfaces the real limits — repository visibility, whether a key is still live,
whether a tarball was downloaded.

```
A Stripe secret key was pushed to a public repo about 40 minutes ago and CI has run twice
since. Give me the ordered response. Be explicit about what happens first and why deleting the
commit is not it. Then tell me what to check in the Stripe dashboard and over what window.
```

Stating the elapsed time and the public visibility changes the answer — it moves the assumption
from "readable" to "already used".

```
Go through every place this project publishes to: git remote, npm, the container registry, the
static host, and the app store build. For each one, tell me what the last publish actually
contained, whether an allowlist or a denylist decided that, and what would leak if someone added
a new directory tomorrow.
```

The last clause tests the control rather than the current state. A denylist that happens to be
correct today is still a denylist.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is my repo safe to make public?" | No scope, no artifact. Produces a general lecture on secret hygiene. Name the history, the tracked files, and the build output |
| "Remove the secret from git history" | Wrong first action, and it is not remediation. Ask for the revocation order first |
| "Add a .gitignore" | Does nothing for files already tracked, which is the actual failure. Ask for the untracking step too |
| "Scan for secrets" | An assistant is a poor entropy scanner. Run `gitleaks` or `trufflehog`, then ask what to do with the hits |
| "Clean up before I push" | Ambiguous — invites formatting changes and deleted files. Say what must not ship |
| "Force push to fix it" | Rewrites hashes, strips signatures, breaks closed-PR diffs, and leaves the value in forks and caches |
| Pasting a real key to ask whether it is exposed | The paste is now an exposure, retained by the model provider. Describe the shape instead |
| "It is a private repo so this is fine" | Not a question, and not true. Private means a smaller audience, not a safe one |
