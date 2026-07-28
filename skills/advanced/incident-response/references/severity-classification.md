# Severity Classification

A severity level answers one operational question: who gets woken up, and how fast. It is not
a judgement of how bad the alert sounded.

Source frame: NIST SP 800-61r3 `RS.MA-03` (incidents are categorized and prioritized) and
`RS.MA-04` (incidents are escalated or elevated as needed). Verified 2026-07-28.

r3 does not define severity levels. It lists risk evaluation factors and says the set "can
range from simple to incredibly complex, depending on the needs and maturity of an
organization." The matrix below is one concrete instance of that; adapt the thresholds, keep
the factors.

## Risk evaluation factors

r3 `RS.MA-03` N2 names these:

| Factor | The question |
|---|---|
| Asset criticality | Does the business stop without this asset? |
| Functional impact | What can users no longer do? |
| Data impact | What data was confidentiality, integrity, or availability affected for? |
| Stage of observed activity | Recon, initial access, persistence, exfiltration, impact? |
| Threat actor characterization | Opportunistic scanner, commodity crimeware, or targeted? |
| Recoverability | Can you restore, and how long does it take? |

Stage of observed activity is the factor teams drop, and it is the one that predicts what
happens next. Confirmed persistence (ATT&CK TA0003) means the attacker plans to come back;
confirmed impact (TA0040) means they have stopped hiding.

## The matrix

| Level | Trigger | Response | Comms |
|---|---|---|---|
| SEV1 | Confirmed unauthorized access to production or customer data, or loss of control of production infrastructure | Page immediately, 24/7. Incident lead plus at least one other responder. Legal and leadership engaged at declaration | Leadership at declaration, then hourly |
| SEV2 | Confirmed compromise of a credential with production reach, no confirmed data access yet | Page during extended hours, respond within 1 hour | Leadership at declaration, then every 4 hours |
| SEV3 | Exposure with limited or expired reach, or a contained single-host compromise | Next business day, tracked as work | Daily written update |
| SEV4 | Suspicious activity, no confirmed unauthorized access | Investigate as normal work | Close-out note only |

Two rules that matter more than the thresholds:

- Start at the severity the worst plausible interpretation implies, then downgrade on evidence.
  Starting low and escalating means the first hour was under-resourced, and the first hour is
  where the volatile evidence lives.
- Never downgrade silently. Write the new level, the timestamp, and the fact that justified it.
  A silent downgrade is indistinguishable from someone getting tired.

## Confirmed versus possible

The matrix keys on "confirmed", so the word has to mean something.

| State | Definition | Example |
|---|---|---|
| Confirmed | A log line, a record in an audit trail, or a captured artefact shows it happened | CloudTrail `GetObject` on the bucket from the attacker's IP |
| Possible | The capability existed and you cannot rule out use | The key had `s3:GetObject` and there is no data-event logging on that bucket |
| Ruled out | The capability did not exist, or complete logs show non-use | The key was scoped to a different account; the trail covers the whole window |

Absence of evidence is not "ruled out" unless you have shown the log covers the window. If
data events were never enabled on that bucket, you have no evidence either way — treat it as
possible and say why in the report. Writing "no evidence of access" when you had no ability to
see access is the sentence that gets quoted back at you later.

## Worked examples

**A GitHub PAT with `repo` and `workflow` scope in a public gist, org has 40 private repos.**

Asset criticality high, data impact potentially all source code, stage unknown, recoverability
fine. Start SEV2: confirmed credential compromise with production reach. It becomes SEV1 the
moment a clone or a workflow run from an unrecognized source appears in the audit log, because
`workflow` scope reaches CI secrets.

**A scanner hitting `/wp-login.php` on an API host that does not run WordPress.**

SEV4. No WordPress, no access, no data. Note it, tune the alert, move on. Ranking this higher
because the log volume looked alarming is how teams train themselves to ignore severities.

**A developer laptop with an EDR alert for a credential-dumping tool, user says they were
testing a security course exercise.**

SEV2 until the story is verified against evidence, not on the say-so. Credential access
(TA0006) on an endpoint with production SSH keys is a production credential exposure. If the
timeline matches the course, artefacts match the course material, and no keys left the host,
close as SEV4 with the reasoning written down.

**An LLM agent with a database tool returned another tenant's records to a user who asked it
to "show all recent orders."**

SEV1 if the records reached the user. Cross-tenant data disclosure is data impact regardless
of whether the mechanism was SQL injection or a model following instructions. The novelty of
the mechanism does not lower the severity — see OWASP LLM01 and LLM06.

**Ransomware note on one file share, backups verified 6 hours old.**

SEV1. Recoverability being good does not lower it: data was encrypted (ATT&CK T1486), and
modern ransomware exfiltrates before encrypting, so assume a data breach until you can show
otherwise. Also check whether the backups themselves were reachable from the compromised
account (T1490) before you count on them.

## Escalation and elevation

r3 distinguishes them, and the distinction is useful:

> Escalation generally refers to increasing resources or time frames, while elevation usually
> indicates involving a higher level of management in the response efforts.

You escalate when the work is bigger than the people on it. You elevate when a decision
belongs to someone with the authority to make it — taking production offline, notifying
customers, engaging law enforcement. Elevating is not admitting failure; making that call
yourself at 3am is.

## Sources

- <https://doi.org/10.6028/NIST.SP.800-61r3> — `RS.MA-03`, `RS.MA-04`
- <https://attack.mitre.org/tactics/TA0003/> · <https://attack.mitre.org/tactics/TA0006/> · <https://attack.mitre.org/tactics/TA0040/>
- <https://attack.mitre.org/techniques/T1486/> · <https://attack.mitre.org/techniques/T1490/>
- <https://genai.owasp.org/llm-top-10/>
