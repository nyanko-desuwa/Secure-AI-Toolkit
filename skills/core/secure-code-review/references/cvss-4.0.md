# CVSS v4.0 — as a communication tool

Common Vulnerability Scoring System version 4.0. Specification document v1.2, dated
2024-06-18. Initial v4.0 publication 2023-11-01, revised v1.1 on 2023-11-09. Verified against
<https://www.first.org/cvss/v4-0/specification-document> on 2026-07-28.

## What it is for, and what it is not for

CVSS describes the intrinsic characteristics of a vulnerability. It is good at making a finding
comparable across teams and at giving a compliance process a number to record.

It is not a triage mechanism. The score has no idea whether the table your SQL injection
reaches holds session tokens or feature flags, whether the affected endpoint gets one request a
day or a million, or whether your organisation cares. FIRST is explicit that severity is not
risk: risk needs threat and environmental context that a Base score deliberately excludes.

In a code review, assign your own severity first from exploitability and blast radius, then add
a CVSS vector if the audience needs one. Not the other way round.

## Base metrics

All eleven Base metrics are mandatory in a vector string, in this order.

Exploitability — the ease and technical means of exploitation:

| Metric | Code | Values |
|---|---|---|
| Attack Vector | AV | N (network), A (adjacent), L (local), P (physical) |
| Attack Complexity | AC | L (low), H (high) |
| Attack Requirements | AT | N (none), P (present) |
| Privileges Required | PR | N (none), L (low), H (high) |
| User Interaction | UI | N (none), P (passive), A (active) |

Impact — split between the vulnerable system and any subsequent system, each H, L, or N:

| Metric | Code |
|---|---|
| Vulnerable System Confidentiality / Integrity / Availability | VC, VI, VA |
| Subsequent System Confidentiality / Integrity / Availability | SC, SI, SA |

Two changes from v3.1 that matter when reviewing code. `AT` is new: it captures a precondition
outside the attacker's control, such as a race that must land or a specific deployment
configuration. And the old single `Scope` flag has been replaced by the Vulnerable/Subsequent
impact split, which is a better fit for findings where a service is the pivot rather than the
target — SSRF reaching a metadata endpoint scores impact on the subsequent system.

## Nomenclature — say which groups you scored

| Label | Metric groups used |
|---|---|
| CVSS-B | Base only |
| CVSS-BT | Base and Threat |
| CVSS-BE | Base and Environmental |
| CVSS-BTE | Base, Threat, and Environmental |

The specification directs that this label be used wherever a numerical score is displayed or
communicated. Use it. A bare "CVSS 8.1" is ambiguous: the reader cannot tell whether exploit
maturity and environmental context were considered.

In v4.0 all three groups always feed the calculation. Unspecified Threat and Environmental
metrics fall back to Not Defined, which assumes the worst case. So a Base-only score is not
neutral — it is the pessimistic end of the range, which is why NVD-style CVSS-B numbers often
read higher than a defender's own assessment.

Threat holds one metric, Exploit Maturity (E). Supplemental metrics — Safety, Automatable,
Provider Urgency, Recovery, Value Density, Vulnerability Response Effort — never change the
score; they carry information for the consumer to act on.

## Vectors for common review findings

Starting points, not answers. Every one of these changes with the deployment.

| Finding | Plausible Base vector |
|---|---|
| IDOR reading another user's record, any logged-in user | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| SQL injection on an unauthenticated endpoint | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| Stored XSS requiring a victim to visit a page | `AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N` |
| SSRF reaching a cloud metadata service | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:H/SI:H/SA:H` |
| Fail-open authorization needing the policy service to be down | `AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |

Note `AT:P` on the last one. The dependency outage is a precondition the attacker does not
straightforwardly control, and that is exactly what Attack Requirements exists to express.

Do not hand-compute the number. v4.0 scoring is a lookup over MacroVector equivalence classes,
not an arithmetic formula you can do in your head, and a guessed score is worse than no score.
Publish the vector and let the reader run it through the official calculator at
<https://www.first.org/cvss/calculator/4.0>.

## Qualitative rating scale

The spec maps scores to ratings: None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 ·
Critical 9.0–10.0.

Where this and your own severity disagree, report both and explain the gap. Usually the gap is
information CVSS-B cannot hold: the endpoint is internal only, or the data is public, or the
affected code path is unreachable in the current deployment. That explanation is the useful
part of the finding.

## Where CVSS misleads in code review

- Availability-only findings score low even when they are the whole business. An unbounded
  export that takes the database down is a `VA:H` and little else, yet it is the outage.
- Chained findings score individually. Three mediums that compose into account takeover are one
  critical, and CVSS has no vector for the chain. Rate the chain in prose.
- Information disclosure and a full read primitive both land on `VC:H` if the data is
  sensitive, which flattens a real difference in effort.
- Authorization findings with `PR:L` score below their real impact in multi-tenant systems,
  because "low privileges" is trivially obtainable when signup is open.
- Business logic flaws often have no honest vector at all. Price manipulation is `VI:H` in a way
  that tells the reader nothing.

## Sources

- <https://www.first.org/cvss/v4-0/specification-document>
- <https://www.first.org/cvss/calculator/4.0>
- <https://www.first.org/cvss/>
