# Shared Checklists

Every skill ships its own `checklist.md`, scoped to what that skill covers. This directory holds
the two checks that do not belong to any single skill: the ones that apply to any change, and the
map that tells you which skill checklists a change actually needs.

Nothing here replaces a skill checklist. If you are touching a database query, run
`skills/core/database-security/checklist.md`. This file exists so you do not stop at one.

## Which checklists does this change need

Read the diff, not the ticket title. Take every row that matches.

| The change… | Run |
|---|---|
| Builds or edits a query | `core/database-security` |
| Loads or mutates an object identified by a request value | `core/api-security`, `core/owasp` |
| Binds request data onto a model or entity | `core/mvc-security` |
| Accepts a path, filename, or upload | `core/file-upload-security` |
| Fetches a URL the user supplied | `core/api-security` |
| Issues, verifies, refreshes, or stores a token | `core/authentication` |
| Accepts a guessable secret: password, OTP, reset token, invite code | `core/brute-force-defense` |
| Renders untrusted data into markup, or sets a cookie or header | `core/frontend-security` |
| Reads a credential, key, or config value | `core/secrets-management` |
| Adds, bumps, or pins a dependency | `core/devsecops` |
| Logs anything derived from user input | `core/logging-audit` |
| Changes a Dockerfile, image, or runtime flag | `core/docker-security` |
| Provisions cloud infrastructure, IAM, or storage | `core/cloud-security` |
| Configures a server, TLS, systemd unit, or deploy | `core/ssh-server` |
| Passes untrusted text to a model, tool, or agent | `core/ai-security` |
| Allocates, caches, subscribes, or opens a handle | `architecture/performance` |
| Handles an error inside a security decision | `core/owasp` |

A single authenticated file-upload endpoint lands on four rows. Stopping at the first match is
how real vulnerabilities survive review.

When the requester cannot review the output themselves, add `core/common-pitfalls` regardless of
what the diff touches. That checklist is written for code that ships unreviewed.

## Universal pre-return checks

These hold for every change, in every skill, in every language. Nothing on this list is
category-specific, which is exactly why it gets skipped.

### The claim

- [ ] Every finding names a standard: Top 10 2025 category, ASVS 5.0 chapter, CWE where one
      applies. An uncited control is an opinion.
- [ ] Every finding has an exploitation path with concrete inputs. If it does not, it is labelled
      a code smell rather than a vulnerability.
- [ ] Severity reflects exploitability and blast radius, not the scariest category name that
      applies.
- [ ] Version-specific claims carry a source URL and the date checked. No recalled category IDs.
- [ ] Nothing invented. An unverifiable requirement number, CVE, or version is left out, not
      guessed.

### The code

- [ ] Authorization is enforced server-side and scoped to the acting subject. No ID, role, or
      tenant trusted from the client (`A01`, `CWE-602`).
- [ ] Input validated at the boundary with an allowlist; output encoded at the sink. Both, not
      one (`A05`, ASVS V1/V2).
- [ ] No string-built queries, commands, or templates. Dynamic identifiers go through an
      allowlist map (`A05`).
- [ ] Errors inside a security decision deny the action. No `except: pass` around a check
      (`A10`, `CWE-390`).
- [ ] Nothing secret in code, fixtures, tests, logs, error messages, or the reply itself
      (`A04`, `CWE-798`).

### The limits

- [ ] Every list endpoint paginates, with a server-enforced maximum page size.
- [ ] Every upload, request body, and batch has a size or count cap.
- [ ] Every outbound call has a connect and read timeout.
- [ ] Every retry loop has a ceiling and backoff.
- [ ] Every cache, queue, and buffer has a bound and an eviction rule (`API4`, `CWE-770`).
- [ ] Every allocation, connection, handle, subscription, listener, and timer has a defined
      owner and a defined end (`CWE-401`, `CWE-772`).
- [ ] No user-controlled value becomes an unbounded cache key.

### The configuration

- [ ] Nothing that is really a policy decision is frozen in source: limits, timeouts, roles,
      tenant IDs, admin addresses, expiries.
- [ ] No debug flag, verbose error, permissive CORS origin, disabled TLS verification, seeded
      credential, or test bypass left in the shipped path (`A02`, `CWE-1188`).
- [ ] Defaults are safe when a config value is absent. Missing config denies rather than allows.

### The report

- [ ] Every unchecked box above is either fixed or stated as a limitation with a reason. An
      unexplained skip reads the same as an oversight.
- [ ] Which skills and checklists were used is named in the reply.
- [ ] What could not be verified is named, including why. "The build did not run because the
      test runner is not installed" is a useful sentence.

## Using these with an assistant

A checklist an assistant marks all-pass without reading the code is worse than no checklist —
it teaches the reader to stop looking. Ask for evidence per item, not a verdict:

```text
Run skills/shared/checklists/README.md against this diff. For each item output pass, fail, or
n/a with the file:line you checked. Mark n/a only with a reason. Do not mark pass on anything
you did not actually read.
```

Then ask the harder question:

```text
Which items did you mark pass without being able to verify them from the source alone?
```

Runtime configuration, deployment state, and whether a control is actually enabled in production
cannot be confirmed by reading code. Those belong in the limitations section of the reply.
