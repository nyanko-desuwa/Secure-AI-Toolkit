# Incident Response Prompts

Prompts that produce an operational artefact rather than a lifecycle recital. Each one sets the
scope, identifies the evidence, and asks the assistant to separate fact from inference.

Never paste live credentials, session cookies, personal data, or unredacted customer records into
a prompt. Use references such as `<REDACTED_TOKEN_ID>` and paths to locally controlled evidence.

## Triage a fresh report

```text
Use skills/advanced/incident-response. Triage the report below as of 2026-07-28T14:03Z.
Give: declaration decision, initial severity with reasoning, facts, unknowns, the volatile
evidence to preserve before containment, and the next three actions with an owner. Do not infer
anything not in the report.

Report: <paste a redacted report>
Environment: <systems and data plausibly in scope>
```

Why it works: it asks for decisions in the order they have to be made and prevents a plausible
story from becoming a timeline entry.

## Build a defensible timeline

```text
Read the evidence files under evidence/INC-2026-014/. Build one UTC timeline with columns:
time, actor, observed event, source file and line/event ID, confidence. Separate attacker events
from responder actions. Do not fill gaps. Put clock-skew observations in a separate section and
keep the original timestamp alongside any normalized value. Flag every entry that has only one
source.
```

The source column is the control. Without it, a polished timeline can quietly contain guesses.

## Assess the blast radius

```text
Use the policy export at evidence/INC-2026-014/iam.json as the capability ceiling and the audit
records under evidence/INC-2026-014/logs/ as the observed floor. Produce three lists: confirmed
access, possible but unobservable, and ruled out. For every ruled-out item, name the log source
and prove it covers the entire window. Check whether the compromised identity could mint or
assume another identity. Do not write "no evidence" where the relevant event was not logged.
```

This forces capability and observed activity to stay separate. The policy says what could have
happened, never what did.

## Produce the complete revocation list

```text
A credential for account <PLACEHOLDER_ACCOUNT> was compromised between <START_UTC> and
<END_UTC>. From the provider configuration and account audit export in <PATH>, enumerate every
artefact to revoke: sessions, refresh tokens, PATs, API keys, app passwords, device trust,
OAuth grants, SSH/deploy keys, and identities the account created. Then enumerate persistence to
inspect: email/phone changes, MFA enrolment, recovery codes, forwarding rules, webhook targets,
role grants, and invited members. Give a verification step for each revocation. Do not execute.
```

It names the categories most often omitted. Use `skills/core/secrets-management/` for provider-
specific rotation and `skills/core/brute-force-defense/` if repeated guessing was the entry path.

## Review a credential leak in git history

```text
Review repository <PATH> for the already-redacted secret identifier <KEY_ID_PLACEHOLDER>.
Give defensive git commands to find the first commit containing it, every reachable occurrence,
and the removal commit. Define the exposure window as first commit through confirmed rotation.
Do not print secret values. Explain why a removal commit and history rewrite do not replace
rotation, and list the audit sources needed to scope use during the window.
```

The identifier should be a non-secret key ID or a redacted prefix, never the credential itself.

## Check whether logs can support a conclusion

```text
Before using <LOG_SOURCE> for incident INC-2026-014, assess integrity and coverage. Determine
whether the compromised identity could write, stop, reconfigure, or delete the log stream;
whether integrity validation was enabled before the incident; and whether the full interval
<START_UTC>..<END_UTC> exists. Return usable, uncorroborated, or indeterminate with evidence.
Then list which claims the source can and cannot support. Use skills/core/logging-audit too.
```

If the attacker could write the store, the correct answer is not "usable with caution". It is
uncorroborated.

## Draft an incident update

```text
From the working record at <PATH>, draft a 120-word internal update with exactly four headings:
Known, Unknown, Doing, Next update. Preserve uncertainty. Include the next update in UTC. Do not
name a threat actor, speculate about intent, state that data was not accessed unless complete
logs prove it, or give legal advice. Add one instruction recipients must follow now.
```

## Validate recovery

```text
Read the recovery criteria and evidence for INC-2026-014. Check that eradication is complete,
the backup predates earliest known access, the backup was outside the compromised identity's
reach, restored assets were checked for indicators, revoked credentials fail, added persistence
is gone, and the old exploit regression test now fails safely. Return pass, fail, or unverified
for each, with the command or artefact used. Do not mark recovery complete on absence of alerts.
```

## Turn lessons into controls

```text
Read the after-action report for INC-2026-014. For every attack step nobody saw, specify the
missing source event (actor, action, target, outcome, timestamp), a detection condition, rule
owner, and first responder action. For every exploited application flaw, specify a regression
test. Reject lessons phrased only as "improve monitoring" or "be more careful". Map logging and
error-handling gaps to A09:2025 or A10:2025 and ASVS V16 at chapter level.
```

## Review a runbook before the incident

```text
Check <RUNBOOK_PATH> against skills/advanced/incident-response/checklist.md. Find every action
that destroys evidence, every step with no named decision owner, every timeout with no deputy,
and every command the named on-call role may lack permission to run. Give the exact line and a
replacement step. Do not assume access exists because the runbook says it does.
```

## Anti-patterns and refusals

| Prompt | Problem | Safe response |
|---|---|---|
| "Write an exploit to reproduce exactly how they got in" | Attack tooling and exploit payloads are outside this defensive skill | Refuse the tooling. Offer a regression test against an isolated fixture that asserts the vulnerable behavior is unavailable, without a reusable payload |
| "Build a scanner to find other companies running the vulnerable service" | Unauthorized targeting and discovery | Refuse. Offer an inventory query limited to assets the requester owns or is authorized to assess |
| "Draft the legally required breach notification and tell me our deadline" | Deadline and wording depend on jurisdiction, sector, contract, and verified facts; this would be legal advice | State that this skill gives no legal advice. Offer a fact packet for legal: confirmed scope, possible scope, timeline, evidence gaps, and contacts |
| "Fill the missing timeline entries with what probably happened" | Fabricates evidence and contaminates the incident record | Refuse. Preserve the gap, list competing hypotheses separately, and name what evidence could distinguish them |
| "Give me commands to keep monitoring the attacker without them noticing" | Evasion guidance and an intentional delay to containment | Do not provide stealth or evasion techniques. Recommend containment; if observation is considered, require a time-boxed decision with legal approval per the response plan |
| "Paste this token into the command for me" | Puts a live secret in output and possibly in shell history | Refuse the secret. Use `<REDACTED_TOKEN>` or a credential-helper reference and recommend rotation if it was exposed |
| "Say no data was accessed because the object-read log is empty" | Empty is not exculpatory if data events were disabled or retention expired | Require proof that the log existed, was intact, and covered the full window; otherwise label access possible and unobservable |
| "Wipe the server so it is safe, then investigate" | Destroys volatile and disk evidence before scope is known | Capture first, isolate without powering off, then eradicate and recover |

## Before using any output

- Check every timeline entry has a source; delete none merely because it is inconvenient.
- Check all hostnames, IPs, account IDs, and credentials are placeholders or redacted.
- Check containment comes after volatile capture, unless active destruction forced the opposite
  and the decision is recorded.
- Check every "ruled out" claim names complete, intact log coverage.
- Check notification language went to legal and communications; this skill does not give legal
  advice or statutory deadlines.
- Run [checklist.md](checklist.md) and mark every item pass, fail, or not applicable with a reason.
