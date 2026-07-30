# Microservices Verification Checklist

Run these checks before returning a design or review. Record evidence or mark the item unverified.

## Ownership and API inventory

- [ ] [recommended] List every service, owner, deployable, datastore, schema, queue, and event topic.
- [ ] [recommended] Name the authoritative owner for every object type.
- [ ] [recommended] Inventory HTTP, gRPC, GraphQL, queue, webhook, health, metrics, debug, and admin endpoints.
- [ ] [recommended] Record audience, authentication, object/action policy, data classification, timeout, rate limit, owner, and deprecation date per API.
- [ ] [critical] Flag shared tables, shared write credentials, cross-service ORM models, and hidden backdoors.

## Identity and authorization

- [ ] [critical] Verify each workload has a distinct identity and least-privilege credentials.
- [ ] [critical] Verify the owner service authenticates the caller and authorizes every object/action/tenant combination.
- [ ] [critical] Confirm object lookup is scoped by the authorized subject or tenant; do not authorize an ID before loading its object.
- [ ] [critical] Check that no `role`, `isAdmin`, `tenantId`, or "authorized" payload field is treated as authority.
- [ ] [recommended] State the confused-deputy consequence when a service acts with its own privilege for another caller.
- [ ] [critical] Record whether end-user context is signed, audience-bound, expiry-checked, and still re-authorized at the owner.

## Transport, discovery, and events

- [ ] [critical] Verify mTLS certificate validation, identity binding, and rotation; state that mTLS is not object authorization.
- [ ] [critical] Allow only approved schemes, service identities, and destinations from discovery; block user-controlled URL resolution and cloud metadata/private ranges where applicable.
- [ ] [critical] Give each producer and consumer separate event permissions and validate event origin and schema.
- [ ] [recommended] Check replay, retention, DLQ, redrive, and event payload minimization.
- [ ] [critical] Confirm outbound calls do not follow arbitrary redirects or forward caller credentials.

## Runtime limits

- [ ] [recommended] Compute connection pools and file descriptors as replicas multiplied by dependencies and pool sizes.
- [ ] [recommended] Set deadlines on every hop and a total request budget.
- [ ] [recommended] Set retry count, jitter, retry budget, idempotency key, and a rule for permanent failures.
- [ ] [recommended] Bound parallel fan-out and fail fast when the dependency budget is exhausted.
- [ ] [recommended] Bound queue bytes/items, consumer concurrency, and DLQ growth; alert on lag and age.
- [ ] [recommended] Bound saga state by count, bytes, sensitivity, and expiry; provide recovery ownership.
- [ ] [recommended] Bound circuit-breaker destination keys, metrics labels, trace cardinality, and cache entries/TTL.

## Migration and rollback

- [ ] [recommended] Define the old and new authority, schema compatibility window, and reconciliation query.
- [ ] [recommended] Start with telemetry or shadow reads that cannot mutate state.
- [ ] [recommended] Gate traffic by percentage, tenant, or object class with an automatic stop condition.
- [ ] [recommended] Make rollback a tested route and define what happens to writes accepted by the new owner.
- [ ] [recommended] Remove dual-write or compatibility paths only after reconciliation and retention windows complete.

## Evidence and reporting

- [ ] [critical] For each finding, record location, capability, impact, fix, runtime cost, residual gap, OWASP category, ASVS chapter, and precise CWE if verified.
- [ ] [recommended] Mark live ACLs, certificate policy, pool limits, queue depth, breaker limits, and cache bounds as unverified when source cannot prove them.
- [ ] [recommended] Report observable limits and dashboards: authorization denials, dependency latency, retries, pool wait, fan-out width, queue age, saga age, trace volume, metric cardinality, and cache size.
- [ ] [recommended] Run the vulnerable/fixed examples and note interpreter/compiler versions used; do not present them as production benchmarks.
