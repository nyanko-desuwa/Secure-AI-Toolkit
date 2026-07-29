# Troubleshooting

When the guidance in this skill cannot be applied cleanly. Every case below is a real conflict,
not an edge case - each one shows up in the first few hours of a serious incident.

The general rule: when two correct instructions disagree, pick one, write down that you picked
it and why, and name what it costs. An undocumented choice looks identical to a missed step.

## Legal hold versus the urge to wipe and rebuild

Engineering wants a clean rebuild. Legal has issued a hold, or a hold is plausibly coming
because of a prosecution, an insurance claim, or litigation.

The hold wins, and it is usually not as expensive as it sounds. Preservation and rebuild are only
in conflict if you rebuild on the same volume. Snapshot the disk, export the logs to storage the
compromised identity never had write access to, hash everything at collection, then build fresh
capacity alongside and cut over.

What not to do: rebuild first and promise to reconstruct evidence from backups. Backups do not
contain memory, deleted files, or the attacker's own artefacts, and a backup taken after initial
access may itself be contaminated.

If you cannot preserve - the instance is already gone, the pod already rescheduled - say so
explicitly and early. Legal can work with a documented gap. They cannot work with a gap they find
out about during discovery.

Formal chain-of-custody handling is not required for every incident; r3 says as much, while
noting collected incident data is still evidence. Once litigation or prosecution is plausible,
custody handling stops being optional and the decision belongs to legal, not to you.

## The regulator clock is running and scope is incomplete

Notification deadlines are wall-clock. Investigations are not. You will be asked for a number
before you have one.

Report the shape rather than a figure: what is confirmed, what is possible and cannot yet be
ruled out, what is ruled out and by which log coverage. A regulator-facing submission that says
"investigation ongoing, X confirmed, upper bound not yet established, next update by <date>" is
normal. A precise figure that changes by two orders of magnitude is the thing that damages
credibility.

Two things this skill will not do: tell you which deadline applies, or draft the notification.
Statutory breach-notification obligations vary by jurisdiction, sector, data type, and contract,
and they change. Contractual and cyber-insurance windows are often shorter than statutory ones
and are missed for that reason. Get legal and your insurer engaged at declaration when personal
data is plausibly in scope, and let them own the clock while you own the facts.

Your job is to make the facts defensible: every claim traced to a log line or labelled as
inference, and every gap in log coverage stated as a gap rather than as an absence of access.

## The business needs uptime and you need the evidence

The compromised host is serving traffic. Somebody senior wants it restarted now.

Both can usually be satisfied, in this order:

1. Shift traffic away - drain the load balancer target, scale up replacements, fail over.
2. Capture volatile state on the now-idle host.
3. Then do whatever recovery wants with it.

That sequence costs minutes, not hours, and it is the answer to almost every version of this
argument. Prepare it before the conversation rather than during it.

When capacity genuinely does not exist and the choice is real, it is a business decision, not
yours. Elevate it: state that restarting destroys the ability to determine what else was
accessed, name who is deciding, and record the decision with a timestamp. Then get whatever is
cheap - disk snapshot, log export, container filesystem copy - even if memory is lost.

Active destruction changes the calculation. If data is being encrypted or deleted right now,
contain immediately and capture what survives. Note in the record that preservation was
sacrificed deliberately.

## An insider is suspected, so the normal channels are unsafe

If the suspected actor has access to the chat platform, the ticketing system, the identity
provider, or the log store, coordinating the response there tells them everything.

Move to a channel outside their reach before writing anything substantive: a separate tenant, a
phone bridge, in person. Keep the participant list small and explicit. Do not open a ticket in
the normal tracker, and do not name the individual in any system they can read.

Involve HR and legal before touching the account. Revoking access is visible and is often an
employment action with process attached; doing it first can compromise both the investigation and
the organization's legal position. Preserve first, then let HR and legal sequence the access
change.

Watch for the second-order problem: if the suspect is an administrator of the log store, your
evidence has the integrity issue described in
[common-mistakes.md](common-mistakes.md#trusting-logs-the-attacker-could-write). Say
"uncorroborated" rather than building a conclusion on records they could edit.

This case is also where a plan pays off most. The runbook should already name the out-of-band
channel and the authority to use it, because deciding under suspicion is how people improvise
into a channel the suspect monitors.

## Containment already happened before anyone read a checklist

Common, and not worth relitigating mid-incident. Do this instead.

Write down exactly what was done and when, in UTC, so the timeline can separate your actions
from the attacker's. Then work out what evidence survived: logs shipped off-host, cloud audit
trails, provider-side audit logs, snapshots, backups, artefacts in CI, container images in the
registry. Provider-side records are the usual save, because they live outside the host that got
wiped.

Then treat every unanswerable question as an explicit gap in the report, and lower your
confidence accordingly. Do not backfill the timeline with plausible reconstruction - an inferred
entry that looks like an observed entry is how a report becomes wrong.

## The logs do not exist for the window you need

Retention rolled the window off, or the events were never generated in the first place. These are
different problems with the same symptom.

Check whether the data exists anywhere else before concluding it is gone: the SIEM may hold
longer retention than the source, cold storage may have the archive, the load balancer or CDN may
have request records the application does not, and provider audit logs are often retained longer
than application logs.

If it is truly gone, the finding is "not observable", never "no unauthorized access". Then extend
retention immediately - before the rest of the investigation window also expires - and record the
missing event class as a post-incident item. Enumerating capability from the identity's policy is
still useful, but it gives you the ceiling, not what happened.

## You cannot tell whether an action was the attacker or a colleague

Two things resolve most of these: ask out of band, and correlate a second independent source.

Ask the named actor through a channel the attacker does not control - not by replying to the
account in question. Then check whether the session, device, IP, user agent, and timing match
that person's normal pattern. Confirmed status requires two independent sources; one log line and
a plausible story is not confirmation in either direction.

Until it resolves, carry it as possible, and say which check would settle it. "Unresolved: key
rotation at 02:14Z, actor claims routine maintenance, no change ticket found" is a useful line in
a report. Silently assuming it was routine is not.

## A checklist item genuinely does not apply

Write the reason on the same line. "No container capture: the workload is a managed database,
no host access" is a complete answer.

An unexplained skip during an incident is indistinguishable from a step nobody did, and the
person reading the record next week has no way to tell them apart.

## Sources

- <https://doi.org/10.6028/NIST.SP.800-61r3> - evidence handling and recovery-initiation guidance
- <https://csrc.nist.gov/pubs/sp/800/86/final> - forensic capture and handoff
- <https://www.rfc-editor.org/rfc/rfc3227.html> - order of volatility
- <https://owasp.org/Top10/2025/> - A09, A10
