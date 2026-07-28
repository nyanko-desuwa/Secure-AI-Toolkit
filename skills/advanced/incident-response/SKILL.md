---
name: incident-response
description: 'Respond to a security incident in a software system without destroying evidence or widening the breach. Frames work with NIST SP 800-61r3 and CSF 2.0. Triggers: "incident response", "breach", "leaked key", "compromised token", "forensics", "sự cố bảo mật", "rò rỉ khoá".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Incident Response

Handle a live security incident in order, and stop the first hour from destroying the
evidence you need in the second.

## Read This First

This skill does not make anyone a forensic investigator. It covers the decisions a
development or platform team makes in the first hours — what to capture, what to revoke,
what to say — and where the handoff to specialists is.

Bring in outside help when any of these are true:

- Ransomware, extortion, or wiper activity
- Suspected nation-state or persistent intruder with lateral movement
- Evidence you intend to use in a prosecution or an insurance claim
- Regulated personal data plausibly accessed
- You cannot establish scope after a day of work

Law enforcement gets contacted per your incident response plan and with management
approval, not ad hoc by whoever noticed. Notification deadlines are legal, jurisdictional,
and not something to reason out during an outage — see `compliance` and your legal team.

## When to Use

- An alert, a report, or a gut feeling suggests unauthorized access
- A credential, key, or token has been exposed
- A CI/CD pipeline, build server, or dependency behaved unexpectedly
- You are writing a runbook, severity matrix, or post-incident review
- You need to reconstruct what happened from logs

## The Frame

NIST SP 800-61 Revision 3 (April 2025) supersedes Revision 2 (2012) and drops the old
four-phase lifecycle in favour of the six CSF 2.0 Functions. The familiar phase names still
work as a mental model; the standard now maps them onto Functions.

| Phase (r2 vocabulary) | CSF 2.0 Functions (r3 Table 1) |
|---|---|
| Preparation | Govern · Identify (all Categories) · Protect |
| Detection and Analysis | Detect · Identify (Improvement) |
| Containment, Eradication, Recovery | Respond · Recover · Identify (Improvement) |
| Post-Incident Activity | Identify (Improvement) |

Improvement (ID.IM) appears in three rows on purpose. r3 says lessons should be shared as
soon as they are identified, not held until recovery ends.

Details, subcategory IDs, and verified quotes in
[references/nist-800-61.md](references/nist-800-61.md).

## Workflow

### 1. Declare and classify

An incident exists when adverse events meet your defined criteria (DE.AE-08). Write the
declaration down with a timestamp. Assign a severity from
[references/severity-classification.md](references/severity-classification.md) and an
incident lead. One lead, named, for the duration.

Do not skip classification because it feels bureaucratic. Severity drives who is woken up
and how fast, and re-deriving it three times in Slack costs more than deciding once.

### 2. Preserve before you touch

Volatile state dies first. Capture memory, process list, network connections, and
container state before containment changes them. Order of volatility is from RFC 3227.

The single most common irreversible mistake is rebooting the host. See
[best-practices.md](best-practices.md#capture-before-you-change-anything) for a collector
script.

### 3. Contain without erasing

Prefer containment that removes the attacker's access while leaving the system observable:
revoke tokens, rotate the key, isolate the network segment, quarantine the container image.
Avoid containment that wipes state: reboot, reimage, `docker rm`, terminate the instance.

`RS.MI-01` is containment, `RS.MI-02` is eradication. They are separate steps and doing them
together is how root cause gets lost.

### 4. Scope the blast radius

What did this credential reach, and what did that token authorize? Answer with logs, not
with the permission policy alone — the policy is the ceiling, the logs are the floor. See
[best-practices.md](best-practices.md#blast-radius-assessment).

Under-scoping is the standard failure. SP 800-61r3 says performing magnitude estimation
superficially allows the incident to continue on other targets without the organization's
knowledge.

### 5. Eradicate, then recover

Remove persistence and entry points: malware, backdoored accounts, injected CI steps,
exploited vulnerabilities. Then restore, verifying backup integrity before you trust it
(`RC.RP-03`). Declare the end of recovery explicitly (`RC.RP-06`).

Recovering before eradication means recovering into the same compromise.

### 6. Communicate

Facts, unknowns, and next update time. Nothing else. See
[best-practices.md](best-practices.md#communication).

### 7. Review without blame

Turn each finding into a regression test or a detection rule, or it did not happen. See
[best-practices.md](best-practices.md#post-incident-review).

## Severity

Rank by confirmed access and blast radius, not by how alarming the alert was. Full matrix
with worked examples in
[references/severity-classification.md](references/severity-classification.md).

- **SEV1** — confirmed unauthorized access to production data or customer data, or loss of
  control of production infrastructure
- **SEV2** — confirmed compromise of a credential with production reach, no confirmed data
  access yet
- **SEV3** — exposure with limited or expired reach, or a contained single-host compromise
- **SEV4** — suspicious activity with no confirmed unauthorized access

Escalate on new facts, never quietly downgrade. Write the reason for any severity change.

## Related Skills

- `compliance` — breach notification obligations and retention requirements. Timing is
  jurisdiction-specific and belongs there, not here
- `secrets-management` — preventing the exposure you are now responding to
- `supply-chain-security` — compromised dependency and build system specifics
- `logging-monitoring` — making logs that support timeline reconstruction
- `owasp-security` — the vulnerability class that let the incident happen

## Supporting Files

- [README.md](README.md) — purpose, standards table, limitations
- [checklist.md](checklist.md) — per-phase verification
- [best-practices.md](best-practices.md) — patterns, with the collector script and queries
- [common-mistakes.md](common-mistakes.md) — what goes wrong under pressure
- [troubleshooting.md](troubleshooting.md) — when the guidance cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/nist-800-61.md](references/nist-800-61.md) — the standard, version-pinned
- [references/severity-classification.md](references/severity-classification.md) — ranking
- [references/runbook-template.md](references/runbook-template.md) — fillable runbook
- [examples/README.md](examples/README.md) — wrong versus right response, eight incidents
