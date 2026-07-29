# Verified CWE Entries for Microservices

Titles and applicability were checked at MITRE CWE on 2026-07-28. Use a precise entry only when the code mechanism matches.

| CWE | Official title | Use here |
|---|---|---|
| CWE-290 | Authentication Bypass by Spoofing | Spoofed workload or producer identity |
| CWE-400 | Uncontrolled Resource Consumption | Retry, fan-out, queue, or connection exhaustion; class-level mapping needs review |
| CWE-441 | Unintended Proxy or Intermediary ('Confused Deputy') | A service uses its authority for an insufficiently authorized caller |
| CWE-602 | Client-Side Enforcement of Server-Side Security | Callee relies on upstream/client authorization |
| CWE-653 | Improper Isolation or Compartmentalization | Shared database or broad shared boundary |
| CWE-770 | Allocation of Resources Without Limits or Throttling | Unbounded pools, state, queues, metrics, or cache |
| CWE-772 | Missing Release of Resource after Effective Lifetime | Connections, transactions, tasks, or saga resources retained |
| CWE-799 | Improper Control of Interaction Frequency | Unbounded retries or repeated side effects |
| CWE-918 | Server-Side Request Forgery (SSRF) | User/event-controlled outbound destination |
| CWE-1220 | Insufficient Granularity of Access Control | Policy too broad for object, action, tenant, or service |

Do not cite a CWE because it is listed in a nearby skill. Verify the mechanism and use one primary mapping per finding. Do not invent a CVE, version, RFC, or requirement identifier.

## Sources

- CWE-290 - <https://cwe.mitre.org/data/definitions/290.html>
- CWE-400 - <https://cwe.mitre.org/data/definitions/400.html>
- CWE-441 - <https://cwe.mitre.org/data/definitions/441.html>
- CWE-602 - <https://cwe.mitre.org/data/definitions/602.html>
- CWE-653 - <https://cwe.mitre.org/data/definitions/653.html>
- CWE-770 - <https://cwe.mitre.org/data/definitions/770.html>
- CWE-772 - <https://cwe.mitre.org/data/definitions/772.html>
- CWE-799 - <https://cwe.mitre.org/data/definitions/799.html>
- CWE-918 - <https://cwe.mitre.org/data/definitions/918.html>
- CWE-1220 - <https://cwe.mitre.org/data/definitions/1220.html>
