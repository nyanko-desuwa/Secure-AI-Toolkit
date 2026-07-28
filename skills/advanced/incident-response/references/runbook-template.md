# Runbook Template

Fill this in before you need it. A runbook written during an incident is a set of guesses.

NIST SP 800-61r3 `ID.IM-04` covers this outcome: incident response plans are established,
communicated, maintained, and improved. r3 gives no template — it deliberately stopped
publishing procedure-level content — so this is a working structure, not a quoted one.
Verified 2026-07-28.

## Per-organization: fill once, review quarterly

```markdown
# Incident Response — Contacts and Authority

## Roles
Incident lead rotation:      <link to on-call schedule>
Security escalation:         <name/alias, phone, out-of-band channel>
Legal contact:               <name, phone>          # required before any law enforcement contact
Comms / public affairs:      <name, phone>
Cloud provider support:      <account ID, support plan tier, case URL>
Retained IR firm:            <firm, contract number, 24/7 number>   # or "none — decide at SEV1"
Cyber insurance:             <policy number, notification requirement, deadline>

## Out-of-band comms
Primary:    <e.g. dedicated Slack workspace, separate tenant>
Fallback:   <e.g. Signal group, phone bridge>
Rule: if the incident may involve the corporate identity provider or chat platform,
      start in the fallback. Do not discuss the intrusion on infrastructure the
      intruder may hold.

## Authority to act
Who can revoke all production credentials without further approval:  <role>
Who can take production offline:                                     <role>
Who can approve customer notification:                               <role>
Who can approve engaging law enforcement:                            <role>
Default if that person is unreachable within N minutes:              <named deputy>
```

The unreachable-deputy line is the one that gets skipped and the one that costs hours.

## Per-incident: the working record

Append-only. Timestamps in UTC with an offset marker, because half the responders will be in
another timezone and relative times ("20 minutes ago") are worthless in a post-mortem.

```markdown
# INC-YYYY-NNN — <short description>

Declared:      2026-07-28T14:03Z  by <name>
Severity:      SEV2               (see severity-classification.md)
Incident lead: <name>             (single, named, for the duration)
Status:        investigating | contained | eradicated | recovering | closed

## Summary
<Three sentences. What we know, what we do not, what we are doing next.>

## Timeline
| UTC | Actor | Event or action | Evidence |
|---|---|---|---|
| 2026-07-28T13:47Z | attacker | First unrecognized login, IP 203.0.113.10 | auth log line 8842, hash <sha256> |
| 2026-07-28T14:03Z | <name> | Incident declared SEV2 | this document |
| 2026-07-28T14:09Z | <name> | Captured volatile state from web-03 | /evidence/INC-2026-014/web-03-mem.raw |
| 2026-07-28T14:15Z | <name> | Revoked token tok_***, sessions invalidated | provider audit event <id> |

Two columns, two kinds of row: what the attacker did, and what we did. Keep them in one
table so cause and effect stay visible.

## Scope
Confirmed accessed:   <list, with the log line that confirms each>
Possible, unproven:   <list, with why it cannot be ruled out>
Ruled out:            <list, with the log coverage that rules it out>

## Indicators
| Type | Value | First seen | Notes |
|---|---|---|---|
| IPv4 | 203.0.113.10 | 13:47Z | Hosting provider, not a residential range |
| UA | <string> | 13:47Z | Not seen before in 90 days of logs |

## Evidence register
| Artefact | Path | SHA-256 | Collected by | When |
|---|---|---|---|---|

## Decisions
| UTC | Decision | Made by | Reasoning | Reversible? |
|---|---|---|---|---|
| 14:12Z | Isolate rather than reimage web-03 | <name> | Preserve disk for root cause | Yes |

Record decisions separately from actions. A post-mortem needs to know why, and the why is
never in a command history.

## Open questions
- [ ] <question> — owner, due
```

## Detection-to-declaration checklist

The first ten minutes, per `DE.AE-08` (incidents are declared when adverse events meet the
defined incident criteria) and `RS.MA-02` (incident reports are triaged and validated).

```markdown
- [ ] Does this meet our written incident criteria? If unsure, declare and downgrade later
- [ ] Severity assigned, worst plausible interpretation first
- [ ] Incident lead named
- [ ] Working record created from this template
- [ ] Comms channel chosen — fallback if IdP or chat may be involved
- [ ] Volatile evidence capture started before any containment
- [ ] Log retention extended on relevant systems     # before the window rolls off
- [ ] Legal notified if personal data or prosecution is plausible
```

Log retention is the sleeper item. Default retention on cloud log groups and CI systems is
often 7 to 30 days, and the intrusion frequently started before that. Extend retention as a
first action, not after you discover the gap.

## Closure

Per `RC.RP-06`, the end of recovery is declared explicitly against criteria, and
documentation is completed. Do not let an incident fade out.

```markdown
- [ ] Eradication verified: persistence removed, entry point closed, exploited flaw fixed
- [ ] Restored assets checked for indicators of compromise before production use  # RC.RP-05
- [ ] Recovery end declared, with timestamp and who declared it                   # RC.RP-06
- [ ] After-action report written                                                  # RC.RP-06 R1
- [ ] Each lesson has an owner and a tracked item                                 # ID.IM-01..04
- [ ] Evidence retained per policy, or destruction recorded
- [ ] Detection rule added for this pattern, or a stated reason none is possible
```

`RC.RP-06` R1 is specific about the after-action report: it documents the incident itself, the
response and recovery actions taken, and lessons learned.

## Sources

- <https://doi.org/10.6028/NIST.SP.800-61r3> — `ID.IM-04`, `DE.AE-08`, `RS.MA-02`, `RC.RP-05`, `RC.RP-06`
- <https://csrc.nist.gov/pubs/sp/800/184/final> — recovery planning
- <https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf> — playbook structure, US federal scope
