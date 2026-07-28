# AI Instructions

Entry point for AI coding assistants. Read this first, before touching any skill file.

`README.md` introduces the project to humans. This file tells you how to use it.

## Read order

Do not load the whole repository. Load in this order and stop when you have enough:

1. **This file** — routing, rules, output contract.
2. **The registry below** — pick the skill that matches the task.
3. **That skill's `SKILL.md`** — workflow and severity rules.
4. **Only the supporting files the workflow points you at.** `checklist.md` before returning
   code, `references/` when you need a category ID or requirement number, `examples/` when
   you need the shape of a fix.

Reading eleven files when the task needs two wastes context that the actual code deserves.

## Skill registry

| Skill | Path | Status | Reach for it when |
|---|---|---|---|
| Common Pitfalls | `skills/core/common-pitfalls/` | Ready | Start here when the requester cannot review the code themselves. Hardcoded values, leaked keys, missing limits, memory leaks |
| OWASP Security | `skills/core/owasp/` | Ready | Any security decision. Default entry point |
| Secure Code Review | `skills/core/secure-code-review/` | Ready | Reviewing existing code in depth, assigning CWE and severity |
| API Security | `skills/core/api-security/` | Ready | REST, GraphQL, gRPC, webhooks, BOLA, rate limits, idempotency |
| MVC Security | `skills/core/mvc-security/` | Ready | Controllers, models, views, ORM, templates, mass assignment |
| Database Security | `skills/core/database-security/` | Ready | Queries, ORM, privileges, tenant isolation, encryption at rest |
| Secrets Management | `skills/core/secrets-management/` | Ready | Env vars, vaults, rotation, workload identity, leak response |
| Logging & Audit | `skills/core/logging-audit/` | Ready | Audit trails, SIEM, masking, log injection, detection rules |
| Docker Security | `skills/core/docker-security/` | Ready | Dockerfiles, images, runtime flags, socket exposure, SBOM |
| SSH & Server | `skills/core/ssh-server/` | Ready | Remote access, Nginx, systemd, TLS, deploys, rollback |
| DevSecOps | `skills/core/devsecops/` | Ready | SAST, DAST, SCA, SBOM, SLSA, CI/CD hardening |
| AI Security | `skills/core/ai-security/` | Ready | Prompt injection, tool injection, MCP, agents, RAG |
| Authentication | `skills/core/authentication/` | Ready | Login, sessions, JWT, OAuth2, OIDC, MFA, RBAC |
| Brute Force Defense | `skills/core/brute-force-defense/` | Ready | Any endpoint where guessing repeatedly wins: login, OTP, reset token, coupon, invite code. Rate limiting, lockout, enumeration, credential stuffing |
| Cloud Security | `skills/core/cloud-security/` | Ready | AWS, Azure, GCP, IAM, storage, network, monitoring |
| File Upload Security | `skills/core/file-upload-security/` | Ready | Uploads, magic numbers, re-encoding, storage isolation, presigned URLs |
| Performance & Resource Lifetime | `skills/architecture/performance/` | Ready | Memory leaks, unbounded caches/queues, listener or connection leaks, OOM, profiling, backpressure |
| Frontend Security | `skills/core/frontend-security/` | Ready | CSP, XSS, CSRF, cookies, iframes, postMessage |
| Publish Safety | `skills/core/publish-safety/` | Ready | Pushing, making a repo public, publishing a package or image, deploying build output, sharing a diff, log, or screenshot |

All skills under `advanced/`, `enterprise/`, and `architecture/` are Ready. Check the full
file set and the skill's checklist before relying on a future addition.

Status means exactly what it says. Ready is complete and safe to rely on. A future skill may have
an entry before its full file set exists; check the directory and do not assume a missing
`checklist.md` means there is nothing to check. Empty means empty: fall back to `core/owasp`, say
which skill would have covered it, and never attribute invented guidance to a skill that does not
exist yet.

## Routing

Match on what the code touches, not on what the user called it. Most changes hit more than one
row — take every row that applies.

| The code… | Load | Category |
|---|---|---|
| Builds a database query | `database-security` | A05 Injection |
| Loads an object by ID from a request | `api-security`, `owasp` | A01, API1 BOLA |
| Binds request data onto a model | `mvc-security` | A01, API3 |
| Accepts a file path or upload | `file-upload-security` | A01 + A08 |
| Fetches a user-supplied URL | `api-security` | A06, API7 SSRF |
| Issues, verifies, or stores a token | `authentication` | A07, ASVS V9/V10 |
| Accepts a guessable secret: password, OTP, reset token, invite or coupon code | `brute-force-defense` | A07, API4, CWE-307/799 |
| Renders untrusted data into a page | `frontend-security`, `mvc-security` | A05, ASVS V1/V3 |
| Reads a credential or config value | `secrets-management` | A02, A04 |
| Adds or bumps a dependency | `devsecops` | A03 Supply Chain |
| Writes a log line containing user data | `logging-audit` | A09 |
| Builds or runs a container | `docker-security` | A02, A03 |
| Provisions cloud infrastructure or IAM | `cloud-security` | A01, A02 |
| Configures a server, TLS, or a deploy | `ssh-server` | A02, ASVS V12 |
| Passes untrusted text to a model or tool | `ai-security` | A05, LLM01 |
| Handles an error inside a security check | `owasp` | A10 |
| Allocates, caches, subscribes, or opens a handle | `performance` | A06, API4, CWE-401/770 |
| Pushes, publishes, deploys, or changes repository visibility | `publish-safety` | A02, A04, CWE-527 |

A single file-upload endpoint typically lands on four rows: upload validation, object
authorization, storage configuration, and audit logging. Stopping at the first match is how
real vulnerabilities survive review.

## Skill discovery before implementation

Do not choose one skill and stop looking. Before writing or changing security-sensitive code:

1. Identify the primary skill from the registry.
2. Search the registry and the repository for related skills that cover adjacent boundaries.
   For example, an API file-upload endpoint needs API Security, File Upload Security, and
   often Authentication or Secrets Management — not just one of them.
3. Read each related skill's `SKILL.md` and load only the supporting files relevant to the
   change.
4. If a related skill is marked Planned or its directory is empty, say so and use the closest
   available guidance. Never pretend an unwritten skill was consulted.
5. Before returning code, run every applicable checklist and report which skills/checklists
   were used.

Security controls cross boundaries. A request handler can simultaneously have an authorization,
file handling, logging, and error-handling failure. Treating the first matching keyword as the
whole review is itself a review failure.

## Learn from real failure patterns

Do not rely on generic security slogans or a single happy-path example. For every security-
sensitive change:

- Look for the real-world failure shape in the relevant skill's `common-mistakes.md`,
  `examples/`, and `references/` before choosing a fix.
- Prefer fixes that remove an unsafe choice structurally: scoped queries over fetch-then-check,
  explicit schemas over mass assignment, narrow tools over prompt instructions, and server-side
  policy over client-side flags.
- Test the abuse case, not only the valid case. Use concrete attacker-controlled inputs,
  boundary values, replay, missing permissions, dependency failure, and partial failure.
- Try to disprove each candidate finding before reporting it. If a precondition is unverified,
  name it and lower confidence rather than inventing certainty.
- When a pattern has a known residual gap, state it. A partial mitigation is not a complete fix.

The goal is not to make code look secure. The goal is to make the demonstrated attack path
unavailable, then show what was checked and what remains unknown.

## Assume the person asking cannot audit your output

Much of the code you write will be accepted without review. The person asking may not read
code, may not know what a token is, and will assume that because it runs, it is finished. That
changes what "done" means: you are the last line of review, not the first draft.

The failures below are the ones that reach production this way. They are not exotic. They are
what shipping fast without a security reviewer looks like.

**Secrets on the client.** An API key in JavaScript, a token in a `NEXT_PUBLIC_` variable, a
service key in a mobile app, a credential in a public repository. Bundling is not hiding — view
source, unminify, read the network tab. Anything the browser can read, the visitor can read. If
a call needs a secret, the call belongs on a server. Say this plainly rather than obscuring the
key and moving on.

**Hardcoded values that were meant to be decisions.** A limit, a timeout, a page size, a role
name, a tenant ID, an admin email, an expiry, a retry count. Each one is a decision frozen at
the moment of writing, invisible later, and usually wrong in production. Worse are hardcoded
security decisions: a bypass flag, a test account, a signature check behind an `if`, an
allowlist with a `localhost` entry that shipped. Name them, surface them, and do not leave one
buried where nobody will find it.

**Missing limits, because the happy path never hit one.** No pagination on a list endpoint, no
upload size cap, no rate limit on login or on an expensive query, no timeout on an outbound
call, no bound on a cache or a queue or a retry loop. Unbounded is not neutral — it is a
resource-exhaustion vector (`API4:2023`, `CWE-770`, `CWE-400`) and the same code path that
leaks memory under load is the one that takes the process down. Performance and security are
the same finding here.

**Debug and convenience left switched on.** Verbose errors and stack traces reaching users,
`DEBUG=True` in production, a permissive CORS origin, TLS verification disabled "to get it
working", a seeded admin password, an exposed `/debug` or `.git` path. These get added to
unblock development and then never removed, because nothing fails when they stay.

**Authorization that only exists in the UI.** A hidden button, a disabled field, a client-side
role check, a filtered dropdown. None of it is a control. The request still works when sent
directly. Every one of these needs a server-side check scoped to the actor.

**Resources that are opened and never released.** Event listeners, intervals, subscriptions,
file handles, database connections, observers, streams. In a long-running process these
accumulate until it dies; on the frontend they accumulate until the tab does. Growth under
normal use is the symptom, and it is a defect whether or not an attacker is involved.

**Trusting input because it usually arrives correct.** Validation on the client only, a schema
that accepts unknown keys, a numeric field parsed with no bounds, a redirect target read
straight from a query parameter, a file typed by its extension.

When you find one of these, do three things: fix it, say what it was in language that makes
sense to someone who does not read code, and say what it would have cost if it had shipped.
"Your Stripe secret key was in the browser bundle, so any visitor could have charged cards
using your account" lands where "moved key to server-side env" does not. `architecture/performance`
holds the leak, limit, and resource-lifecycle detail; the relevant core skill holds the rest.

## Before you publish anything

This is a blocking gate, not advice. It applies whenever you are about to make something in the
user's project readable by someone who cannot read it today: `git commit`, `git push`,
`npm publish`, `pip upload` / `twine upload`, `docker push`, a deploy command, a repository
visibility change, or pasting a diff, log, or screenshot into a public place.

Publishing is a one-way door. Once a credential is public, no commit, force-push, unpublish, or
deleted repository takes it back — the only remediation is revocation at the provider. So the
check happens before, because afterwards there is nothing left to check.

Run `skills/core/publish-safety/checklist.md` for the surface you are about to touch, and report
the result. Then:

1. **Do not run the publishing command until the checklist has been run and reported.** If you
   cannot run it — no shell access, no repository — say so and hand the commands to the user
   rather than proceeding as if it passed.
2. **Stage named paths. Never `git add -A` or `git add .`.** Blanket staging is how an untracked
   local file becomes a tracked one, and the commit that adds it is what puts it in history.
3. **Any hit stops the sequence.** Report what would leak, what it would cost in language the
   user can act on, and wait. Do not publish and then mention it.
4. **`git status` is the present tense; a public repository exposes the whole history.** Scan
   history before any visibility change, and scan the built artifact rather than the source.
5. **You may create or edit the user's `.gitignore`, `.dockerignore`, `.npmignore`, and the
   `files` field, and you may generate `.env.example` by stripping values — never by copying
   `.env`.** Report exactly what you added, line by line. This is the only write authority this
   gate grants you at the publish boundary.
6. **Do not rewrite history, force-push, or delete remote refs to clean up a leak.** Those are
   the user's call, they break every existing clone, and they are not the remediation anyway.
   Revoke first — `skills/core/secrets-management/references/exposure-response.md` has the order.
7. **Gitignored and local-only files stay out.** Private notes, personal instruction files,
   scratch directories, editor state: never staged, never quoted in a commit message, never cited
   in a file that will be committed. A file being in the repository root does not make it part of
   the project.

## Rules

These hold regardless of which skill is loaded.

1. **Cite the standard.** Every control names its Top 10 category and ASVS chapter, plus a
   CWE where one applies. An uncited control is an opinion.
2. **Authorization is server-side and per-object.** Scope the query by the actor. Never trust
   an ID, role, or tenant that arrived from the client.
3. **Validate at the boundary with an allowlist. Encode at the sink.** Validation shrinks the
   input space; encoding is what makes the sink safe. They are not substitutes.
4. **Parameterize.** No string building in SQL, ever. Dynamic identifiers go through an
   allowlist map.
5. **Fail closed.** An error inside a security decision denies the action.
6. **No secrets in output.** Not in code, not in fixtures, not in logs, not in your reply.
   Reference by key name.
7. **Run the checklist before returning code.** Every unchecked box is a fix or a stated
   limitation with a reason. An unexplained skip is indistinguishable from an oversight.
8. **Verify version-specific claims.** Fetch the source rather than recalling a category ID.
   Editions renumber.
9. **Release what you acquire.** Every allocation, connection, file handle, subscription,
   listener, timer, and cache entry needs a defined owner and a defined end. Unbounded growth
   is a denial-of-service path, not just a performance bug — see `architecture/performance`
   (CWE-401 Missing Release of Memory, CWE-772 Missing Release of Resource, CWE-770
   Allocation Without Limits).
10. **Do not expand scope.** Fix the file you are in. Note inconsistencies elsewhere without
    sweeping them up.
11. **Check before you publish.** Nothing becomes readable by a wider audience — a push, a
    commit, a package, an image, a deploy, a visibility flip, a shared screenshot — until the
    gate above has been run and its result reported. Stage named paths only. See
    `skills/core/publish-safety/`.

## Loading budget

Skills cost context. A task that loads twelve of them has less room left for the code than a task
that loaded three, and the review gets worse, not better.

Per task, load at most: **five** `core/` skills, **two** `advanced/`, **one** `enterprise/`, and
**one** `architecture/`. Dependencies count against the budget.

`skills/shared/references/skill-graph.md` says which skills assume another's guidance
(`depends_on`) and which cover an adjacent boundary (`related`). Load a skill's direct
`depends_on`, and theirs, and stop — depth two. Transitive closure on that graph reaches most of
the repository, which is what the budget exists to prevent.

If the chain would exceed the budget, load the primary skill plus its direct `depends_on`, then
name what you did not load and why. A stated omission is reviewable; a silent one is not.

## Before you return

In this order, because each step can invalidate the one before it:

1. **Re-read the diff you are about to hand over**, not your memory of writing it.
2. **Run every applicable `checklist.md`.** An unchecked box is a fix or a stated limitation with
   a reason.
3. **Try to disprove each finding.** An unverified precondition lowers confidence; it does not
   get rounded up to certainty.
4. **Check the publish gate** if anything is about to be committed, pushed, or shared.
5. **Report what you could not verify.** Which skills and checklists you used, which commands you
   actually ran versus handed over, and what remains unknown. "The build did not run, so the fix
   is unverified" is a complete sentence and a useful one.

## Output contract

For each finding, give exactly this:

- **Category** — Top 10 ID, ASVS chapter, CWE where applicable
- **Location** — `file:line`
- **Exploitation path** — concrete inputs or state, and what the attacker gets
- **Fix** — the change, and why it closes the hole rather than just looking safer
- **Severity** — with reasoning

A finding with no exploitation path is a code smell. Label it as one. Ranking by category
name is wrong: SQL injection on an integer cast in an admin-only route is not critical.

Severity is exploitability plus blast radius:

- **Critical** — unauthenticated access to other users' data, or code execution
- **High** — authenticated privilege escalation, injection behind auth
- **Medium** — needs an unlikely precondition, or leaks non-sensitive detail
- **Low** — defence in depth missing, no direct path

## Conflicts

When two standards seem to disagree, they usually do not. The Top 10 is a risk ranking; ASVS
is a requirement set. Implement the ASVS requirement, report with the Top 10 category.

When a secure fix conflicts with a project constraint, prefer the more security-focused
option, state that you made the call, and say what it costs. When the fix breaks existing
behaviour, stop and report: current behaviour, what changes, who breaks, migration path. A
breaking change to auth is not a call you make alone.

See `skills/core/owasp/troubleshooting.md` for the longer list.

## Honesty

State what you checked and what you could not. "Exploitable if `sort` reaches the query
unvalidated — I could not find the caller" is useful. "Critical SQL injection" without
checking is noise, and noise gets checklists ignored.

Never claim a fix is verified if the build or tests did not run. Say why they did not.

## Pinned versions

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 | 2026-07-28 |
| OWASP API Security Top 10 | 2023 | 2026-07-28 |
| OWASP ASVS | 5.0.0 | 2026-07-28 |

The 2025 Top 10 is not a renumbering of 2021. `A03:2025 Software Supply Chain Failures` and
`A10:2025 Mishandling of Exceptional Conditions` are new, and Injection moved from A03 to
A05. Guidance recalled from 2021 will mis-map. Details in
`skills/core/owasp/references/owasp-top10-2025.md`.

## When you change this repository

Documentation is part of the change. Before finishing:

- New or modified skill → update its `README.md`, `checklist.md`, and `examples/`
- New skill → add a row to the registry above, the routing table, the `README.md` status table,
  `skills/shared/references/skill-graph.md`, and `skills/shared/references/standards-matrix.md`
- New skill → add the reverse edge in the graph, too. A one-directional `related` is an oversight
- Any change → add a `CHANGELOG.md` entry under Unreleased
- Standard re-verified → update the version and date in the reference file, the table above,
  and `README.md` together

Every new skill matches the file shape and meets the bar in
`skills/shared/templates/README.md`. Scaffold in `skills/shared/templates/skill-scaffold/`.

Placeholder text left in a file means the skill is not done. Empty directories are honest;
half-written guidance is not.
