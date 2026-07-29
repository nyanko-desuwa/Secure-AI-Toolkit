# CWE entries for architectural findings

Verified 2026-07-28 against <https://cwe.mitre.org/>. Each entry below was read on its own CWE
page; the abstraction level and mapping guidance are quoted from that page.

Architectural findings need a CWE so they can be tracked alongside implementation bugs. The
difficulty is that most useful architecture CWEs sit at Class or Pillar level, and CWE
discourages mapping real vulnerabilities to those. Use the Base entries where one fits, and say
plainly when you are citing a Class because no Base entry matches the design flaw.

## The entries

| CWE | Name | Abstraction | Mapping guidance |
|---|---|---|---|
| CWE-653 | Improper Isolation or Compartmentalization | Class | ALLOWED |
| CWE-1220 | Insufficient Granularity of Access Control | Base | ALLOWED |
| CWE-250 | Execution with Unnecessary Privileges | Base | - |
| CWE-1188 | Initialization of a Resource with an Insecure Default | Base | ALLOWED |
| CWE-602 | Client-Side Enforcement of Server-Side Security | Class | ALLOWED-WITH-REVIEW |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Base | ALLOWED |
| CWE-668 | Exposure of Resource to Wrong Sphere | Class | DISCOURAGED |
| CWE-693 | Protection Mechanism Failure | Pillar | DISCOURAGED |

## What each one is for

CWE-653 - Improper Isolation or Compartmentalization. "The product does not properly
compartmentalize or isolate functionality, processes, or resources that require different
privilege levels, rights, or permissions." The right citation for a shared database with no
tenant separation, a single service handling both admin and public traffic, or one blast radius
covering everything. Note a discrepancy on the CWE page itself: the header lists Class, while
the mapping rationale text refers to it as Base.

CWE-1220 - Insufficient Granularity of Access Control. Base level, so preferred for mapping.
Access controls exist but "lack required granularity", so the policy is too broad. Use this for
a role that grants more than the job needs, a token scoped to a whole API instead of one
operation, or an IAM policy with a resource wildcard.

CWE-250 - Execution with Unnecessary Privileges. An operation runs "at a privilege level that is
higher than the minimum level required". Containers as root, a service account with cluster
admin, a database user that can DDL when it only reads.

CWE-1188 - Initialization of a Resource with an Insecure Default. A default meant to be changed
later by an installer or administrator, where the default itself is not secure. Renamed from
"Insecure Default Initialization of Resource" in October 2023. This is the CWE for a fail-open
default, a config flag that defaults to permissive, or a new tenant created with sharing on.

CWE-602 - Client-Side Enforcement of Server-Side Security. "The product is composed of a server
that relies on the client to implement a mechanism that is intended to protect the server." Use
for price or quantity validated only in the browser, feature flags gating a paid capability
purely in the frontend, or a mobile app that decides its own entitlements.

CWE-359 - Exposure of Private Personal Information to an Unauthorized Actor. The privacy
counterpart. Child of CWE-200. Use when a design exposes personal data to actors lacking
authorization or the person's consent - over-broad internal access, analytics events carrying
identifiers, logs that replicate PII into a system with different access rules.

CWE-668 - Exposure of Resource to Wrong Sphere. Class, and explicitly DISCOURAGED for mapping
because it gets used as a catch-all. Mentioned here so you recognise it and reach for something
more specific.

CWE-693 - Protection Mechanism Failure. Pillar level, DISCOURAGED for mapping as too
high-level. Occasionally useful as a category header in a report. Never as the CWE on a finding.

## Choosing one

| Finding | CWE |
|---|---|
| Tenants share a table with no row-level enforcement | CWE-653 |
| Role grants read on all customers when the job needs one | CWE-1220 |
| Container runs as root; service account is cluster admin | CWE-250 |
| Missing config means "allow"; new resource defaults to public | CWE-1188 |
| Browser decides the price, the entitlement, or the role | CWE-602 |
| Design puts PII where more people can read it than need to | CWE-359 |

## Related

- CWE Top 25 - <https://cwe.mitre.org/top25/>
- OWASP Top 10 2025 A01, A02, A06
- OWASP ASVS 5.0 V8, V13, V15
