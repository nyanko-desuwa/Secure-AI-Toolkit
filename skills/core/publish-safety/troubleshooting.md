# Troubleshooting

What to do when the gate cannot be run cleanly. Every entry ends in an action.

The one rule that resolves most of these: publishing is a one-way door, so when you are stuck,
the safe side of the decision is always "do not publish yet". Nothing on this page is a reason to
push anyway.

## The secret is already public and rotating it breaks production

Rotate anyway if the scope is write or admin. A live admin credential in a public place is being
used by someone else, not just readable by them - public-repo commits are scraped within minutes.

For a read-scoped credential you may have room to sequence it:

1. Issue the replacement first and deploy it.
2. Revoke the old value.
3. Write down the window between exposure and revocation, because that is the window you have to
   audit.

Do not let "we will revoke after the next release" become the plan without a date attached. The
ordered response and the per-credential revocation commands are in
[secrets-management/references/exposure-response.md](../secrets-management/references/exposure-response.md).

## History rewrite is impossible: shared clones, forks, open PRs

Then do not attempt it, and stop treating it as the fix. Rewriting history was never the
remediation; revocation is.

GitHub's own guidance puts rotation first and says outright that if you only rewrite history and
force-push, the commits "may still be accessible elsewhere" - in clones, in forks, in cached views
reachable by SHA, and through pull requests that reference the old commits. Force-pushing does not
update read-only `refs/pull/` refs at all.

What to do instead:

- Revoke and rotate. That is the whole remediation.
- Add the control that stops the next one: pre-commit scanning, server-side push protection, an
  allowlist manifest.
- If, and only if, the value cannot be rotated - a private key embedded in shipped hardware, a
  third-party credential whose owner is gone - escalate to the platform's support for cache and PR
  ref removal, and expect them to ask what you did about rotation first.

Rewriting history also has costs worth naming before you start: every commit hash after the rewrite
point changes, signatures are stripped, closed-PR diffs break permanently, and a collaborator who
pulls with a stale clone re-introduces the data.

## The value is in a fork you do not control

You cannot clean it. You cannot make the fork owner clean it, and the platform will not give you
their contact details.

Treat the value as permanently public and revoke. Then check whether the fork is still receiving
your commits, because if it is, the next leak lands there too.

## The scanner flags something that is not a secret

Confirm it is not, then narrow the rule rather than disabling the scanner.

- A test fixture, an example key from documentation, a public key, a hash: exclude that specific
  path or fingerprint, with a comment saying why.
- A value that looks random but is not secret - a build ID, a content hash: same, with a comment.
- If you cannot tell whether it is live, rotate it. The cost of rotating a non-secret is a deploy;
  the cost of publishing a secret is not bounded.

Never resolve a red scan with a blanket skip. A skipped scan is recorded in the audit log on both
GitHub and GitLab, and reviewers read it as "there was a secret here".

## Revocation needs someone who is unreachable

Escalate rather than wait. In order:

1. Reduce what the credential can reach right now, even if you cannot delete it - remove the IAM
   policy, drop the database role's privileges, disable the integration on your side, block the
   token at a gateway.
2. Say plainly, in the report, that the credential is still live and who owns it.
3. Set a follow-up with a date.

A finding that ends in "waiting on the vendor" with no compensating control is not handled.

## You must publish today and the scan is not finished

Reduce the surface instead of skipping the gate:

- Publish an allowlist. Set `files` in `package.json` or `MANIFEST.in` to the exact build output.
  An allowlist you can read in ten seconds is stronger than a full-history scan you have not run.
- For a repository, keep it private and grant access to the specific people who need it. Private is
  not safe, but it is a smaller audience than public and it is reversible.
- Run the narrow checks: `git log --all --full-history -- ".env*" "*.pem" "*.key"`, then `npm pack
  --dry-run` or `docker history`. Those take seconds and catch the common cases.
- Report what you did not check. "History before 2024 was not scanned" is a usable sentence for the
  person deciding.

What not to do: publish and plan to scan afterwards. There is no afterwards on this door.

## Push protection blocked the push and the value is legitimate

Do not reach for the bypass first. Work out whether the value needs to be in the repository at all.

- If it is a real credential: remove it, rotate it, and read the value from configuration instead.
- If it is a test fixture: make it obviously fake. Prefix it with `EXAMPLE` or `PLACEHOLDER` so the
  next scanner and the next reader both stop worrying about it.
- If it genuinely must ship - a public key, a signed manifest - use the platform's documented
  bypass with an accurate reason. On GitHub the reason chosen determines whether the alert stays
  open, and a bypass generates an audit entry and notifies repository admins. On GitLab the skip
  method, account, and commits are all recorded.

Choosing "false positive" for something that is not one is worse than the original push, because it
closes the alert.

## `.gitignore` is not working

Almost always because the file is already tracked. `.gitignore` governs untracked files only; once
a path is in the index, ignore rules have no effect on it.

```bash
git ls-files --error-unmatch path/to/file   # tracked? then that is the cause
git check-ignore -v path/to/file            # which rule matched, if any
git rm --cached path/to/file                # untrack, keep on disk
```

Untracking removes it from future commits and from the published worktree. It does not remove it
from history - see the rewrite entry above, and rotate.

## Two guidance items conflict

Common cases, and how they resolve:

- "Clean the history" versus "revoke first". Revoke first, always. Cleanup is hygiene and is
  optional; revocation is the remediation.
- "Commit `.env.example` so onboarding works" versus "never commit credential files". Both hold:
  commit the example with empty or obviously fake values, and gitignore every real `.env` with a
  `!.env.example` negation.
- "Publish the lockfile for reproducibility" versus "keep the tarball minimal". Publish it. It
  contains no credentials, unless someone put a token in a registry URL - check that instead of
  dropping the file.
- "Ship the source for debuggability" versus "do not publish internal detail". Ship a source map to
  an error tracker with restricted access rather than to public hosting.

If the conflict is real and the security-focused option costs something the project cares about,
take the security-focused option, say that you made the call, and name the cost.

## You cannot tell whether a finding is exploitable

Report it with the precondition attached. For this skill the usual unknowns are:

- Whether the repository is actually public. You cannot see visibility from the working tree.
- Whether the credential is still live. Only the provider can say.
- Whether the artifact was ever downloaded. Only the registry's stats can say.

"`SUPABASE_SERVICE_ROLE_KEY` appears in `dist/assets/index-4f3a.js`, which is deployed to static
hosting. I could not confirm whether the key is still valid - rotate and check the provider's usage
log" is a useful finding. An unqualified severity label is not.

## A checklist item genuinely does not apply

Write the reason. "No package registry: this repository is not published as a package" is a
complete answer. An unexplained skip reads exactly like an oversight.

## The standard or the platform has moved on

The versions and platform behaviours in [references/](references/) were verified on `2026-07-28`.
Registry precedence rules, push-protection defaults, and tier availability all change. If a decision
turns on one of them, re-fetch the source rather than trusting the pin, and update the reference
file with the new date.

Never assume undocumented behaviour, especially about what a platform deletes on your behalf.
