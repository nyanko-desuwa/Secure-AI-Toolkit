# Review Prompts

These prompts name the artifact, attacker position, boundary, output shape, and runtime cost. Replace paths with the project paths under review.

## Inventory every API

```text
Read routes, RPC registrations, queue consumers, webhooks, health, metrics, debug, and admin
handlers under services/. Build a table with protocol, method, path/topic, owner, caller/audience,
authentication, object/action authorization location, tenant scope, data classification, timeout,
rate limit, retry policy, dependency fan-out, and deprecation date. Mark unknown live controls as
unverified. Do not omit endpoints because they are called internal.
```

## Review service identity

```text
Read service-to-service client and server configuration. For every hop, identify the authenticated
workload, certificate or token validation, audience, rotation, and failure behavior. Separate mTLS
transport authentication from object authorization. Flag source-IP, service-name strings, caller
headers, shared secrets, and fail-open policy. Map each finding to A07/A02, ASVS V6/V12/V13, and
one verified CWE only.
```

## Find object-authorization gaps

```text
For every read, update, delete, export, refund, and admin operation, trace subject, action, object,
tenant, and policy decision from ingress to the owning service. Show the object lookup predicate and
the deny path. Flag gateway-only checks, caller-supplied role/tenant/amount/authorized fields,
ID-before-tenant lookup, background jobs, event consumers, and caches. Report capability, location,
fix, cost, residual gap, A01/A06 and ASVS V8.
```

## Detect confused deputies

```text
Find calls where a service uses its own broad credential to act for an end user. For each, state the
privilege the callee has, the caller-controlled input, the object it can reach, and the resulting
confused-deputy path. Rewrite with bounded, audience-bound user context and owner-side authorization.
Include how revocation and service compromise change the blast radius. Cite CWE-441 only if the
verified reference supports the exact mechanism.
```

## Review mTLS claims

```text
List every place the design says mTLS, mesh, private network, or internal means trusted. For each,
separate peer authentication, endpoint permission, and per-object authorization. Show the missing
check and a fixed decision tuple (workload, subject, action, object, tenant, context). Include
certificate rotation, expiry, handshake cost, and what source review cannot prove at runtime.
```

## Review discovery for SSRF

```text
Trace every destination from request/event/config input through service discovery, DNS, redirects,
and outbound sockets. Flag arbitrary URLs, user-controlled service names, scheme changes, forwarded
credentials, private/control-plane destinations, and unbounded DNS/connection attempts. Recommend a
finite logical dependency map, identity validation, HTTPS, redirect policy, egress policy, timeout,
and response-size limit. Cite A01/A05, ASVS V4/V15, CWE-918 where applicable.
```

## Review event trust

```text
For every producer and consumer, list broker permissions, schema validation, signature/origin check,
actor context, object re-authorization, deduplication, replay window, retention, DLQ, and alert owner.
Reject the claim that signing or topic membership authorizes a business action. Include payload
minimization and queue/storage growth. Use the event-driven skill for detailed E hazards.
```

## Cost a split before implementation

```text
Given N replicas, D outbound dependencies, pool size P, fan-out F, retry attempts R, queue capacity
Q, saga retention T, trace spans S, breaker keys K, and cache entries C, calculate the upper bounds and
failure amplification. State which values are hard limits and what happens when each is reached. Do
not recommend a service split unless an independent deploy, scale, availability, compliance, or team
boundary earns the network and operations cost.
```

## Plan a reversible migration

```text
Plan a strangler migration for [module]. Define old/new authority, contract compatibility, data
ownership, shadow-read evidence, bounded backfill, cohort routing, stop thresholds, reconciliation,
rollback routing, writes accepted during rollback, queue/event handling, and deletion of compatibility
code. Include API inventory updates, authorization tests, deadlines, retry budgets, queue/saga limits,
and dashboards. Mark assumptions and unverified runtime facts.
```

## Anti-patterns

| Vague prompt | Likely weak result | Better constraint |
|---|---|---|
| “Make it microservices” | Many deployables with no owner or rollback | Ask which independent boundary earns the split |
| “Add mTLS” | Transport encryption presented as authorization | Require peer identity, endpoint policy, and object policy separately |
| “Secure internal APIs” | Gateway or network trust | Inventory every route and owner-side deny path |
| “Use service discovery” | Arbitrary URL or registry trust | Require finite identities, destination validation, and egress limits |
| “Split the database” | Tables copied with no authority | Name one writer, reconciliation, and retention |
| “Add retries” | Uncapped retry storm | Supply deadline, jitter, budget, idempotency, and permanent-failure route |
| “Make it scalable” | More replicas and multiplied pools | Calculate pools, fan-out, queues, traces, caches, and breaker keys |
| “Plan migration” | Big-bang rewrite | Require cohorts, stop thresholds, reconciliation, and tested rollback |
| “Add observability” | High-cardinality logs and traces | Give limits for spans, labels, queues, and retained attributes |
| “Is this architecture secure?” | General reassurance | Name one service boundary, one object action, and one failure path |
