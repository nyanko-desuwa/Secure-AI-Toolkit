# Architecture Verification Checklist

Run before returning a design, a design review, or an IaC change. Mark each item pass, fail, or
not applicable. "Not applicable" needs a one-line reason.

Only the sections the change touches need running. Adding a read-only internal endpoint does not
need the privacy section.

## Trust Boundaries (A01 · ASVS V8)

- [ ] [recommended] Every boundary crossing is listed, including build system → production and operator → data
- [ ] [critical] Each crossing names what is authenticated, what is authorized, and the failure behaviour
- [ ] [critical] No crossing is authenticated by network position, source IP, or an unsigned header
- [ ] [critical] No component trusts a claim it received from a component it does not control
- [ ] [critical] Internal service calls carry a principal, not just a shared secret proving "I am inside"

## Authorization Placement (A01 · ASVS V8 · CWE-1220)

- [ ] [critical] The component that holds the data makes the authorization decision
- [ ] [recommended] Gateway or middleware checks are labelled as defence in depth, not as the only check
- [ ] [critical] No entitlement, price, quantity, or role is decided by the client (CWE-602)
- [ ] [critical] Every new endpoint is unreachable until a policy is attached to it
- [ ] [critical] Bulk, export, admin, and background paths carry the same checks as the single-object read

## Tenant and Identity Isolation (A01 · ASVS V8 · CWE-653)

- [ ] [critical] Tenant identity comes from the authenticated session, never from a request field
- [ ] [critical] Cross-tenant access is impossible by construction, not by remembering a `WHERE` clause
- [ ] [critical] Caches, queues, search indexes, and object storage keys are tenant-scoped
- [ ] [recommended] Per-tenant encryption keys where the threat model calls for them, with a named reason if not
- [ ] [critical] Background jobs and admin tooling go through the same tenant scoping as request paths

## Least Privilege (A01 · ASVS V8 · CWE-250)

- [ ] [critical] Every identity - human, service, CI - is scoped to specific operations and resources
- [ ] [critical] No wildcard resource in an IAM policy that touches customer data
- [ ] [critical] Database credentials match the access needed: read-only stays read-only, no DDL at runtime
- [ ] [recommended] Workloads do not run as root, and do not mount a token they never call the API with
- [ ] [recommended] Production access for humans is time-bound, reviewed, and logged, or does not exist

## Secure Defaults (A02 · ASVS V13 · CWE-1188)

- [ ] [critical] Missing configuration denies rather than allows
- [ ] [critical] A new tenant, user, or resource starts private and unshared
- [ ] [critical] Debug, verbose error, and introspection surfaces default off and cannot be enabled per request
- [ ] [recommended] Encryption in transit and at rest is the default path, not an opt-in flag
- [ ] [recommended] The insecure option, where one exists, is loud: named `INSECURE_`, logged at startup

## Data Flows and Privacy (A01, A02 · ASVS V14 · CWE-359)

- [ ] [recommended] Personal data is inventoried per store, with a purpose and a retention period
- [ ] [recommended] Personal data does not flow into logs, analytics, or error reporting by default
- [ ] [recommended] Data crossing a boundary into a system with weaker access rules is minimised or masked
- [ ] [recommended] Deletion actually deletes: backups, caches, search indexes, and downstream copies covered
- [ ] [recommended] Third-party processors are named, and the field-level data each one receives is written down

## Failure Modes (A06, A10 · ASVS V16)

- [ ] [critical] Every dependency has a defined failure behaviour, and no security check fails open
- [ ] [critical] Auth provider unavailable denies new sessions rather than granting them
- [ ] [recommended] Timeouts, retry limits, and circuit breakers exist on every outbound call
- [ ] [critical] Partial failure leaves no half-applied privilege change or orphaned grant
- [ ] [recommended] Degraded mode is a designed state with a written control list, not an accident

## Abuse Cases (A06)

- [ ] [recommended] Abuse cases written alongside use cases, from the attacker's goal backwards
- [ ] [recommended] Rate limiting on expensive, sensitive, and enumeration-prone flows, per actor and per IP
- [ ] [critical] Sequence and state are enforced server-side; steps cannot be skipped or replayed
- [ ] [optional] The insider case considered: what a support agent or an on-call engineer can reach
- [ ] [optional] Economic abuse considered where the flow costs money to serve

## Service Boundaries (A01, A06 · ASVS V15 · CWE-653)

- [ ] [recommended] Services are split by trust level and blast radius, not only by team convenience
- [ ] [recommended] Admin and public surfaces are separate deployments, or the split reason is written down
- [ ] [recommended] No shared database write path used as an implicit interface between services
- [ ] [critical] Compromise of the least trusted service does not reach the most sensitive data
- [ ] [recommended] Egress is restricted; a compromised service cannot dial arbitrary destinations

## Auditability (A09 · ASVS V16)

- [ ] [recommended] Security-relevant mutations cannot occur without an audit record
- [ ] [recommended] Audit records include actor, action, target, outcome, timestamp, and tenant
- [ ] [recommended] Audit storage is append-only relative to the services that write to it
- [ ] [recommended] Someone is alerted on the events that matter, not just recorded

## Decision Record

- [ ] [recommended] Every accepted risk has an ADR: threat, options, choice, residual risk, owner
- [ ] [recommended] Compensating controls named where the primary control was rejected
- [ ] [recommended] Time-bound exceptions carry an expiry date, not "revisit later"
- [ ] [optional] The diagram in the repo matches the system as designed

## Before Returning

- [ ] [recommended] Findings state which are architectural and which are implementation
- [ ] [recommended] Every finding names its standard and a CWE where one fits
- [ ] [critical] Anything unverifiable - runtime state, deployed config - said plainly
- [ ] [recommended] Severity reasoning given, not just a label
