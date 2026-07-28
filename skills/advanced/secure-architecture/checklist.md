# Architecture Verification Checklist

Run before returning a design, a design review, or an IaC change. Mark each item pass, fail, or
not applicable. "Not applicable" needs a one-line reason.

Only the sections the change touches need running. Adding a read-only internal endpoint does not
need the privacy section.

## Trust Boundaries (A01 · ASVS V8)

- [ ] Every boundary crossing is listed, including build system → production and operator → data
- [ ] Each crossing names what is authenticated, what is authorized, and the failure behaviour
- [ ] No crossing is authenticated by network position, source IP, or an unsigned header
- [ ] No component trusts a claim it received from a component it does not control
- [ ] Internal service calls carry a principal, not just a shared secret proving "I am inside"

## Authorization Placement (A01 · ASVS V8 · CWE-1220)

- [ ] The component that holds the data makes the authorization decision
- [ ] Gateway or middleware checks are labelled as defence in depth, not as the only check
- [ ] No entitlement, price, quantity, or role is decided by the client (CWE-602)
- [ ] Every new endpoint is unreachable until a policy is attached to it
- [ ] Bulk, export, admin, and background paths carry the same checks as the single-object read

## Tenant and Identity Isolation (A01 · ASVS V8 · CWE-653)

- [ ] Tenant identity comes from the authenticated session, never from a request field
- [ ] Cross-tenant access is impossible by construction, not by remembering a `WHERE` clause
- [ ] Caches, queues, search indexes, and object storage keys are tenant-scoped
- [ ] Per-tenant encryption keys where the threat model calls for them, with a named reason if not
- [ ] Background jobs and admin tooling go through the same tenant scoping as request paths

## Least Privilege (A01 · ASVS V8 · CWE-250)

- [ ] Every identity — human, service, CI — is scoped to specific operations and resources
- [ ] No wildcard resource in an IAM policy that touches customer data
- [ ] Database credentials match the access needed: read-only stays read-only, no DDL at runtime
- [ ] Workloads do not run as root, and do not mount a token they never call the API with
- [ ] Production access for humans is time-bound, reviewed, and logged, or does not exist

## Secure Defaults (A02 · ASVS V13 · CWE-1188)

- [ ] Missing configuration denies rather than allows
- [ ] A new tenant, user, or resource starts private and unshared
- [ ] Debug, verbose error, and introspection surfaces default off and cannot be enabled per request
- [ ] Encryption in transit and at rest is the default path, not an opt-in flag
- [ ] The insecure option, where one exists, is loud: named `INSECURE_`, logged at startup

## Data Flows and Privacy (A01, A02 · ASVS V14 · CWE-359)

- [ ] Personal data is inventoried per store, with a purpose and a retention period
- [ ] Personal data does not flow into logs, analytics, or error reporting by default
- [ ] Data crossing a boundary into a system with weaker access rules is minimised or masked
- [ ] Deletion actually deletes: backups, caches, search indexes, and downstream copies covered
- [ ] Third-party processors are named, and the field-level data each one receives is written down

## Failure Modes (A06, A10 · ASVS V16)

- [ ] Every dependency has a defined failure behaviour, and no security check fails open
- [ ] Auth provider unavailable denies new sessions rather than granting them
- [ ] Timeouts, retry limits, and circuit breakers exist on every outbound call
- [ ] Partial failure leaves no half-applied privilege change or orphaned grant
- [ ] Degraded mode is a designed state with a written control list, not an accident

## Abuse Cases (A06)

- [ ] Abuse cases written alongside use cases, from the attacker's goal backwards
- [ ] Rate limiting on expensive, sensitive, and enumeration-prone flows, per actor and per IP
- [ ] Sequence and state are enforced server-side; steps cannot be skipped or replayed
- [ ] The insider case considered: what a support agent or an on-call engineer can reach
- [ ] Economic abuse considered where the flow costs money to serve

## Service Boundaries (A01, A06 · ASVS V15 · CWE-653)

- [ ] Services are split by trust level and blast radius, not only by team convenience
- [ ] Admin and public surfaces are separate deployments, or the split reason is written down
- [ ] No shared database write path used as an implicit interface between services
- [ ] Compromise of the least trusted service does not reach the most sensitive data
- [ ] Egress is restricted; a compromised service cannot dial arbitrary destinations

## Auditability (A09 · ASVS V16)

- [ ] Security-relevant mutations cannot occur without an audit record
- [ ] Audit records include actor, action, target, outcome, timestamp, and tenant
- [ ] Audit storage is append-only relative to the services that write to it
- [ ] Someone is alerted on the events that matter, not just recorded

## Decision Record

- [ ] Every accepted risk has an ADR: threat, options, choice, residual risk, owner
- [ ] Compensating controls named where the primary control was rejected
- [ ] Time-bound exceptions carry an expiry date, not "revisit later"
- [ ] The diagram in the repo matches the system as designed

## Before Returning

- [ ] Findings state which are architectural and which are implementation
- [ ] Every finding names its standard and a CWE where one fits
- [ ] Anything unverifiable — runtime state, deployed config — said plainly
- [ ] Severity reasoning given, not just a label
