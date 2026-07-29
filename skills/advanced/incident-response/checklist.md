# Incident Response Checklist

Run the phase you are in. Mark each item pass, fail, or not applicable, and give a one-line
reason for every "not applicable" - an unexplained skip during an incident is indistinguishable
from a step nobody did.

Order matters here in a way it does not in a code review checklist. The preservation section
runs before the containment section, every time. If you are reading this mid-incident and
containment already happened, jump to `troubleshooting.md#containment-already-happened`.

## Declaration (DE.AE-08 · RS.MA-02 · RS.MA-03)

- [ ] Declaration written down with a UTC timestamp and the person who declared it
- [ ] Severity assigned from the worst plausible interpretation, not the average one
- [ ] One incident lead named, and they are not also the person running commands
- [ ] Working record created from `references/runbook-template.md`
- [ ] Comms channel chosen; fallback channel used if the IdP, chat platform, or email may be involved
- [ ] Reporter's original message copied verbatim into the record before anyone paraphrases it
- [ ] Legal notified if personal data or a prosecution is plausible (do not wait for certainty)

## Evidence preservation (RS.AN-06 · RS.AN-07)

- [ ] Log retention extended on every relevant system before anything else
- [ ] Volatile state captured in RFC 3227 order: memory, network state, process list, then disk
- [ ] Disk or volume snapshot taken before reboot, reimage, terminate, or `docker rm`
- [ ] Cloud audit trail exported to a bucket the compromised credential cannot write to
- [ ] Every artefact hashed at collection, hash recorded in the evidence register
- [ ] Collector output written off-host, not into the filesystem being investigated
- [ ] Container logs and ephemeral filesystem copied before the pod is deleted or rescheduled
- [ ] Nobody has logged into the suspect host interactively without recording that they did
- [ ] Timestamps recorded in UTC with an explicit offset marker

## Containment (RS.MI-01)

- [ ] Containment action chosen for reversibility; irreversible options rejected or justified in writing
- [ ] Credential revocation covers every artefact derived from it: sessions, refresh tokens, API keys, PATs, app passwords, device tokens
- [ ] Revocation verified by attempting to use the credential, not by trusting the console
- [ ] Network isolation preserves the host's running state rather than powering it off
- [ ] Blast radius of the containment action itself assessed - who else loses access
- [ ] Decision to observe rather than contain, if taken, is time-boxed and approved by legal (RS.MA-05)
- [ ] Attacker-controlled channels not used to coordinate the response
- [ ] Containment actions logged in the working record with UTC times, so the timeline can separate attacker activity from ours

## Scoping (DE.AE-03 · DE.AE-04 · RS.AN-08)

- [ ] Log coverage for the window confirmed before writing "no evidence of access"
- [ ] Every action the compromised identity took in the window enumerated from logs, not inferred from its policy
- [ ] Earliest evidence of access found, then searched backwards past it for the real first access
- [ ] Other identities the compromised one could mint, assume, or reset checked
- [ ] Data-plane access checked separately from control-plane access (object reads are often not logged by default)
- [ ] Findings split into confirmed, possible, and ruled out, each with the log line or the gap that puts it there
- [ ] Secondary use of the same credential elsewhere checked: CI, third-party integrations, developer laptops
- [ ] Correlation across at least two independent sources for anything reported as confirmed

## Eradication (RS.MI-02)

- [ ] Entry point identified and closed, not just the observed symptom
- [ ] Persistence checked in every place the identity could write: scheduled jobs, CI workflow files, OAuth app grants, added SSH keys, forwarding rules, webhooks, new IAM users or roles, MFA enrolments
- [ ] Newly created accounts and access grants in the window reviewed one by one
- [ ] Exploited vulnerability actually fixed, with a test that fails on the old code
- [ ] Third-party tokens the attacker could have read from the environment rotated too
- [ ] Eradication verified by an independent check, not by the absence of new alerts

## Recovery (RS.MA-05 · RC.RP-02 · RC.RP-03 · RC.RP-05 · RC.RP-06)

- [ ] Recovery criteria met before recovery starts - eradication done, not in progress
- [ ] Backup integrity verified, and the backup predates the earliest evidence of access
- [ ] Backup checked for reachability from the compromised identity before it is trusted
- [ ] Restored assets scanned for indicators before they take production traffic
- [ ] Normal operating status confirmed by a check that would fail if the compromise persisted
- [ ] End of recovery declared explicitly, with a timestamp and a name
- [ ] Monitoring for the same indicators left in place after closure, for longer than feels necessary

## Communication (RS.CO-02 · RS.CO-03 · RC.CO-03 · RC.CO-04)

- [ ] Each update states facts, unknowns, current actions, and the next update time
- [ ] No speculation about attribution, cause, or impact presented as fact
- [ ] Nothing stated as ruled out that is only unobserved
- [ ] Customer-facing statements approved by whoever holds that authority in the runbook
- [ ] Internal audience told what to do, not just what happened
- [ ] Updates continue on schedule even when there is nothing new; say "no change"

## Post-incident (ID.IM-01 · ID.IM-03 · ID.IM-04 · RC.RP-06)

- [ ] After-action report covers the incident, the response, and the lessons
- [ ] Timeline separates what the attacker did from what we did
- [ ] Detection gap named for every step of the attack nobody saw, mapped to A09 and CWE-778
- [ ] Each lesson has a named owner and a tracked item, not a paragraph
- [ ] At least one regression test or detection rule merged, or a written reason none is possible
- [ ] Runbook updated with what was missing while you needed it
- [ ] Review held without attributing the incident to an individual's mistake
- [ ] Evidence retained per policy, or its destruction recorded

## Logging and error handling follow-ups (A09 · A10 · ASVS V16)

- [ ] Missing security events added at the source, with actor, action, target, outcome, timestamp (CWE-223)
- [ ] Any secret found in a log treated as a second incident, rotated, and the log line remediated (CWE-532)
- [ ] Log retention on the systems that mattered raised beyond the investigation window
- [ ] Alerting closed the loop: the event now fires a rule, and the rule has a documented action
- [ ] Data-event logging enabled where the scoping gap was "we could not see object access"
- [ ] Fail-open error handling found during the investigation fixed to fail closed

See `skills/core/logging-audit/checklist.md` for the full logging verification list. Do not
duplicate that work here; link to it in the after-action report.

## Before you report

- [ ] Every claim in the report traces to a log line, an artefact, or is labelled as inference
- [ ] Gaps in coverage stated plainly, with what you could not see and why
- [ ] Severity in the report matches the evidence, including any change and its reason
- [ ] Temporary analysis files and copied credentials removed from working machines
