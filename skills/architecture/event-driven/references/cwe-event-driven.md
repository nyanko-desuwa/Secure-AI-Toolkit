# CWE Entries Cited in This Skill

Every title below was checked at <https://cwe.mitre.org> on 2026-07-28. Nothing is quoted from
memory. If a finding needs a CWE that is not here, look it up before writing the number down — a
plausible-looking ID that turns out to be about something else discredits the whole report.

| CWE | Title | Abstraction | Mapping usage |
|---|---|---|---|
| CWE-290 | Authentication Bypass by Spoofing | Base | Allowed |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Base | Allowed |
| CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition | Base | Allowed |
| CWE-390 | Detection of Error Condition Without Action | Base | Allowed |
| CWE-400 | Uncontrolled Resource Consumption | Class | see note |
| CWE-401 | Missing Release of Memory After Effective Lifetime | Base | see note |
| CWE-502 | Deserialization of Untrusted Data | Base | Allowed |
| CWE-522 | Insufficiently Protected Credentials | Class | Allowed-with-Review |
| CWE-532 | Insertion of Sensitive Information into Log File | Base | Allowed |
| CWE-602 | Client-Side Enforcement of Server-Side Security | Class | Allowed-with-Review |
| CWE-770 | Allocation of Resources Without Limits or Throttling | Base | see note |
| CWE-772 | Missing Release of Resource after Effective Lifetime | Base | see note |
| CWE-799 | Improper Control of Interaction Frequency | Class | Allowed-with-Review |
| CWE-841 | Improper Enforcement of Behavioral Workflow | Class | Allowed |
| CWE-863 | Incorrect Authorization | Class | Allowed |
| CWE-1220 | Insufficient Granularity of Access Control | Base | Allowed |

Note on 400, 401, 770, 772: titles and distinctions are maintained in
`skills/architecture/performance/references/cwe-resource-leaks.md`, which owns the
resource-lifecycle taxonomy for this repository. That file was verified on the same date. This
skill cites them and links there rather than restating the guidance.

## The two that carry the skill

CWE-602 Client-Side Enforcement of Server-Side Security — "the product is composed of a server
that relies on the client to implement a mechanism that is intended to protect the server."

The word "client" is the reason people miss this one for event-driven code. There is no browser
involved, so it does not look like a client-side enforcement bug. It is exactly one. The consumer
is the server for the action it performs, and the producer is the client that supplied the
decision. When the consumer charges a card because the message said `authorized: true`, the
protection mechanism lives entirely on the side that the consumer does not control. Class level,
mapping Allowed-with-Review, so pair it with a Base-level child or with CWE-863 when you can be
more specific.

CWE-863 Incorrect Authorization — the product does perform an authorization check but "does not
correctly perform the check." Use this when the consumer checks something, and the something is
wrong: a role from the payload, a tenant from the payload, an allow-list keyed on a producer name
that any publisher can write. Use CWE-862 territory only when there is no check at all, and verify
that entry yourself before citing it — it is not in this skill's verified set.

Pick one. CWE-602 describes where the decision was made; CWE-863 describes that the check was
wrong. Both on one finding is redundant.

## The rest, and what distinguishes them

CWE-290 Authentication Bypass by Spoofing — "incorrectly implemented authentication schemes that
are subject to spoofing attacks." The right entry for producer identity taken from a
`source: "order-service"` field in the payload rather than from the broker's authenticated
principal. Base level, child of CWE-1390 Weak Authentication in the research view.

CWE-359 Exposure of Private Personal Information to an Unauthorized Actor — the product fails to
stop private data reaching actors "not explicitly authorized to access the information" or without
the subject's implied consent. This is the fat-event citation. It fits both directions: a new
subscriber that now receives fields it was never entitled to, and a replay that re-emits personal
data months after the request. Base level, mapping Allowed.

CWE-502 Deserialization of Untrusted Data — the product "deserializes untrusted data without
sufficiently ensuring that the resulting data will be valid." A message body is untrusted data by
definition once you accept that the broker is a network boundary. Applies to `pickle.loads`, Java
default typing, and any format where a field in the payload selects the class to construct. Base
level, mapping Allowed, medium exploit likelihood.

CWE-522 Insufficiently Protected Credentials — credentials transmitted or stored "using an
insecure method that is susceptible to unauthorized interception and/or retrieval." Covers one
shared broker password in every service's config and in every container image. Class level,
Allowed-with-Review — MITRE points at Base-level children such as CWE-256 and CWE-523 for a
tighter fit, so check those if the specific mechanism matters.

CWE-532 Insertion of Sensitive Information into Log File — "the product writes sensitive
information to a log file." The poison-message handler that logs the full body. Worth citing
precisely because the log usually has broader read access than the topic did, which makes it a
second and weaker route to the same data. Base level, Allowed, medium exploit likelihood. Titles
before 2020 differ, so a search may surface the older wording.

CWE-799 Improper Control of Interaction Frequency — the product "does not properly limit the
number or frequency of interactions that it has with an actor." Two uses here: a retry loop with
no ceiling hammering a failing dependency, and a duplicate side effect applied once per
redelivery. Class level, Allowed-with-Review.

CWE-841 Improper Enforcement of Behavioral Workflow — the product "does not properly ensure that
the actor performs the behaviors in the required sequence." The ordering citation. A handler that
applies `order.shipped` before `order.created`, or overwrites a newer state with an older event,
is this weakness. Class level, child of CWE-691, mapping Allowed.

CWE-1220 Insufficient Granularity of Access Control — a policy exists but is "too broad because it
allows accesses from unauthorized agents to the security-sensitive assets." MITRE's canonical
example is hardware: one policy bit covering both read and write. The software analogue that fits
here is a broker where publish rights on a topic are granted to a group rather than a principal,
or one credential that can produce and consume on everything. Base level, mapping Allowed.

## Deliberately not cited

Named so nobody assumes they were forgotten:

- Exactly-once claims and lost messages after a dual write. That is a correctness defect. No CWE
  is a good fit, and forcing one weakens the report. Say "the event is lost, the read side is
  permanently wrong" and move on.
- Server-side request forgery from a URL inside an event payload. Real, and it has its own entry
  that is not in this skill's verified set.
- Message-broker-specific CVEs. Version-dependent, and inventing one is the worst possible error
  in a security document. Check the vendor advisory.
- Race conditions in a saga's compensating action. Adjacent, and this skill does not verify your
  locking.

## Using one in a report

Attach the CWE to the mechanism, not the symptom. "Duplicate charges, CWE-799" says nothing
actionable. "`handleOrderPlaced` at `consumers/billing.ts:41` writes the charge with no dedupe
key; SQS delivery is at-least-once, so each redelivery charges again — CWE-799" names what is
missing and where.

## Sources

- CWE-290 — <https://cwe.mitre.org/data/definitions/290.html>
- CWE-359 — <https://cwe.mitre.org/data/definitions/359.html>
- CWE-367 — <https://cwe.mitre.org/data/definitions/367.html>
- CWE-390 — <https://cwe.mitre.org/data/definitions/390.html>
- CWE-502 — <https://cwe.mitre.org/data/definitions/502.html>
- CWE-522 — <https://cwe.mitre.org/data/definitions/522.html>
- CWE-532 — <https://cwe.mitre.org/data/definitions/532.html>
- CWE-602 — <https://cwe.mitre.org/data/definitions/602.html>
- CWE-799 — <https://cwe.mitre.org/data/definitions/799.html>
- CWE-841 — <https://cwe.mitre.org/data/definitions/841.html>
- CWE-863 — <https://cwe.mitre.org/data/definitions/863.html>
- CWE-1220 — <https://cwe.mitre.org/data/definitions/1220.html>
- CWE-400, 401, 770, 772 — see
  `skills/architecture/performance/references/cwe-resource-leaks.md`
