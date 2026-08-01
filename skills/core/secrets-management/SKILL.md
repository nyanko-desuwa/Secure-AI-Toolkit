---
name: secrets-management
description: 'Decide how secrets are stored, delivered, rotated, and revoked. Covers the storage hierarchy, secret managers, workload identity, rotation windows, and leaked-secret response. Triggers: "secret", "API key", "credentials", "Vault", "rotation", "leaked token", "bí mật", "khoá API".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Secrets Management

A secret is a credential whose disclosure lets someone else act as you. This skill is about
where it lives, how it reaches the process, how it changes, and what you do the hour after it
leaks.

## When to Use

- Adding any credential: database password, API key, signing key, webhook secret, token
- Writing a Dockerfile, CI pipeline, Kubernetes manifest, or Terraform module
- Designing rotation, or discovering there is none
- Responding to a secret found in git, in a log, in an image, or in a chat message
- Reviewing code that compares, logs, or forwards a credential

## The Hierarchy

Worst to best. Each rung buys something specific and still leaks something specific.

| Rung | Buys | Still leaks |
|---|---|---|
| Hardcoded in source | Nothing | Everyone with repo read, every fork, every CI log, every AI context window. CWE-798 |
| `.env` committed | The illusion of separation | Identical to hardcoded. The file is in history |
| `.env` gitignored | Not in git | On every developer laptop, in backups, in `docker cp`, in editor crash files |
| Env vars at runtime | Not on disk in the repo | Process listings, `/proc/<pid>/environ`, crash dumps, child processes, error reporters. CWE-214 |
| Secret manager, long-lived value | Central audit, revocation, one place to rotate | The fetched value still lands in process memory and can still be logged |
| Secret manager, short-lived credential | Blast radius bounded by TTL | The bootstrap identity used to fetch it |
| Workload identity, no stored secret | Nothing to steal at rest | Token theft from inside the workload, and trust policy misconfiguration |

The jump that matters most is from "a value a human can copy" to "an identity a machine
proves". Everything above env vars is refinement; that jump is the change in kind.

## Workflow

### 1. Inventory

List every credential the change touches and answer three questions for each:

- Where does the value come from at runtime?
- Who and what can read it today?
- What happens if it is disclosed right now - can you revoke it in one action?

If you cannot answer the third, there is no rotation story and that is the finding.

### 2. Place it on the hierarchy

Name the current rung and the next reachable one. "Hardcoded, move to env var" is progress.
"Hardcoded, move to Vault with IRSA" is often correct and often not this sprint. State both.

### 3. Deliver it

Pick the access pattern for the platform. See
[best-practices.md](best-practices.md#secret-managers) for Vault, AWS, Azure, and GCP with
working code, and [references/secret-manager-comparison.md](references/secret-manager-comparison.md)
for the tradeoffs.

Cache with a TTL shorter than the credential's lifetime. Never cache to disk.

### 4. Design rotation before you need it

Rotation is a dual-secret window, not a swap. The verifier accepts old and new
simultaneously for one overlap period. Build that in on day one - retrofitting it during an
incident is how rotation becomes an outage. See
[best-practices.md](best-practices.md#rotation).

### 5. Close the leak paths

Walk the list of places secrets end up by accident: CI variables, image layers, build args,
Kubernetes Secrets, Terraform state, log output, error trackers, LLM prompts and tool
arguments. [checklist.md](checklist.md) has all of them.

### 6. Verify

Run [checklist.md](checklist.md). Every unchecked box is a fix or a stated limitation.

## On Exposure

Order matters and it is counterintuitive.

1. Revoke. Make the old value useless. Do this before you understand the incident.
2. Rotate. Issue the replacement and deploy it.
3. Investigate. Read the audit log for use of the credential between exposure and revocation.

Deleting the commit is not step zero and is not remediation. See
[references/exposure-response.md](references/exposure-response.md).

## Severity

Rank by what the credential can do and how long it stays valid, not by where it was found.

- **Critical** - a live production credential with write or admin scope, no expiry, in a
  place outside your control (public repo, public image, third-party log sink)
- **High** - a live production credential in a place with broad internal read (private repo
  history, CI log, shared Kubernetes namespace)
- **Medium** - a scoped or short-lived credential exposed internally, or a production
  credential in a place only a few principals read
- **Low** - a development-only credential with no production reach, or a missing
  defence-in-depth control with no current exposure

A hardcoded key is not automatically critical. A hardcoded test key for a sandbox tenant is
low. Say which and why. Conversely a "read-only" key is not automatically medium - read on
the customer database is a breach.

## Related Skills

- `devsecops` - pre-commit hooks, CI secret scanning, pipeline configuration
- `cloud-security` - IAM policy shape, trust policies, KMS
- `docker-security` - image layers, build context, runtime configuration
- `kubernetes-security` - RBAC, encryption at rest, CSI secret drivers
- `incident-response` - the wider process around the revoke/rotate/investigate loop
- `logging-audit` - redaction pipelines and what belongs in an audit trail
- `publish-safety` - the check before a push, a package, or a visibility flip makes a value public
- `payments-security` - webhook signing keys and payment API secrets are in scope here

## Supporting Files

- [README.md](README.md) - purpose, configuration, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when the guidance cannot be applied
- [prompts.md](prompts.md) - prompts that produce findings
- [references/](references/) - standards, manager comparison, exposure response
- [examples/](examples/) - eight vulnerable/fixed pairs
