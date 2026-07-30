# Ports and Adapters Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. A not-applicable answer
needs one sentence of justification; silence reads the same as an oversight.

## Port Inventory

- [ ] [recommended] Every port is listed with its direction: driving (an adapter calls in) or driven (the core calls out)
- [ ] [recommended] Every port interface is declared inside the core, not next to the adapter that implements it
- [ ] [recommended] Every driving port has its full list of adapters named: HTTP, queue, CLI, cron, test harness
- [ ] [optional] No port has exactly one adapter without a written reason (security boundary, or an untestable dependency)
- [ ] [recommended] No port method names a transport, ORM, or broker type in its signature
- [ ] [recommended] Driven ports return domain types, not rows, HTTP responses, or broker messages
- [ ] [recommended] The count of arrows crossing the core boundary is known, because that is the number of places a check can be forgotten

## Actor and Authorization (`A01:2025` · ASVS V8)

- [ ] [critical] Every security-relevant driving port method takes the actor as a required, non-optional parameter
- [ ] [critical] The actor is not read from a request-scoped global, thread local, or `context.Value` inside the core
- [ ] [critical] The authorization decision happens inside the use case, behind the port, not in any adapter
- [ ] [critical] Each inbound adapter builds the actor from a credential it verified itself, never from a body field or header
- [ ] [critical] The tenant on the actor comes from the verified credential, not from client input (`CWE-602`)
- [ ] [critical] An empty or partially populated actor is rejected, not treated as anonymous
- [ ] [critical] Queue, cron, and CLI adapters supply a named principal with narrow roles, not a superuser (`CWE-1220`)
- [ ] [recommended] Construction of system or service actors is restricted, greppable, and audited
- [ ] [recommended] Missing and not-owned return the same result where existence is sensitive
- [ ] [critical] Authorization failure denies; a failure in the policy's own dependency also denies (`A10:2025`)

## Inbound Adapter: Validation and Mapping (ASVS V2, V4)

- [ ] [critical] Payload parsing, schema validation, and unknown-field rejection happen in the adapter
- [ ] [recommended] The core receives a command type it defines, not a parsed transport payload
- [ ] [critical] Body, header, and upload sizes are bounded at the adapter before parsing
- [ ] [recommended] Every inbound adapter applies the same validation, verified adapter by adapter, not assumed
- [ ] [critical] The wire schema is separate from the domain type, so a new domain field is not mass-assignable (`API3:2023`)
- [ ] [recommended] A new adapter added in this change was checked against every item in this section

## Driven Adapter: Outbound Safety

- [ ] [critical] No port method accepts a query fragment, SQL string, filter expression, or query builder (`A05:2025`, `CWE-89`)
- [ ] [critical] Repository adapters use parameterized queries and apply the tenant predicate inside the adapter
- [ ] [critical] Any port that fetches a user-influenced URL, host, or path is treated as an SSRF surface (`API7:2023`, `CWE-918`)
- [ ] [critical] The egress adapter checks every resolved address, refuses private and link-local ranges, and pins or disallows redirects
- [ ] [recommended] The DNS-rebinding residual risk is stated, and the chosen mitigation is named
- [ ] [critical] Third-party responses are size-bounded, schema-validated, and never deserialized into arbitrary types (`CWE-502`)
- [ ] [recommended] Retries have an attempt cap, total budget, jitter, and an idempotency rule (`CWE-400`)

## Error Translation (`A10:2025` · `CWE-209` · ASVS V16)

- [ ] [recommended] Domain errors are core types; no framework exception crosses into the core
- [ ] [recommended] Each adapter maps core errors to its own protocol; no domain exception is rendered raw
- [ ] [critical] Client responses carry a stable code, no stack trace, no SQL text, no internal identifier
- [ ] [critical] An unmapped error maps to a generic failure, not to a default that reveals internals
- [ ] [recommended] The detail is logged with a correlation id; the correlation id is what the client receives
- [ ] [recommended] Authorization denial and dependency timeout remain distinguishable in logs and metrics

## Adapter Resource Lifetime (`CWE-772`, `CWE-401`, `CWE-400`, `CWE-770`)

- [ ] [recommended] Every client, pool, and connection is created once at composition time, not per call
- [ ] [recommended] Every long-lived client has a bounded pool, an idle timeout, and a request timeout
- [ ] [recommended] Every adapter that acquires a resource exposes a close or stop method, and composition calls it
- [ ] [recommended] Shutdown order is stop accepting, drain in-flight, then release pools
- [ ] [recommended] Every subscription, listener, and timer registered by an adapter has a matching removal on stop
- [ ] [recommended] No port returns a lazy iterator, stream, or cursor whose handle the core cannot close
- [ ] [recommended] Where streaming is required, the port makes the lifetime explicit (a closer, a callback, or a bounded batch)
- [ ] [recommended] Any in-memory adapter used as a cache or stand-in store has a maximum size and eviction
- [ ] [recommended] Any queue between an inbound adapter and the core has a bounded depth and a defined full-behaviour
- [ ] [critical] The actor travels with the queued job; nothing is re-elevated on the async path

## DI and Composition

- [ ] [critical] No adapter registered as a singleton holds request-scoped state: actor, tenant, connection, cursor
- [ ] [recommended] Per-request or per-message adapters are registered at that scope, or the state is a method parameter
- [ ] [recommended] A singleton worker opens and disposes one scope per job or message
- [ ] [recommended] The container's captive-dependency validation runs in CI, or the graph was drawn by hand
- [ ] [recommended] Whoever creates a resource releases it; the container disposes only what it created

## Cost

- [ ] [optional] Every interface added in this change has a named second implementation or a written security reason
- [ ] [optional] Mapping steps per request per direction are counted, and hot list paths project directly
- [ ] [recommended] Query count is known for every list path that goes through a repository port
- [ ] [recommended] A test asserts query count where N+1 is plausible
- [ ] [recommended] Socket, file-handle, and buffer ceilings per adapter are stated, not guessed
- [ ] [recommended] No claim of faster, safer, or lower-memory behaviour is made without a measurement

## Tests

- [ ] [recommended] A fake driven adapter exists for each driven port used in tests
- [ ] [critical] The fake does not skip a check the real adapter performs; tenant scoping is enforced in both
- [ ] [recommended] One contract suite runs against both the fake and the real adapter, the real one in CI
- [ ] [critical] At least one abuse test per driving port: wrong owner, wrong tenant, empty actor, injected role
- [ ] [recommended] Abuse tests assert on state, not only on the returned error
- [ ] [critical] Each inbound adapter has a test that an unauthenticated call produces no actor at all

## Fit

- [ ] [optional] A second adapter for each new port can be named, or the port is a deliberate security boundary
- [ ] [optional] The framework's own idioms were considered for a single-entry-point CRUD path and rejected for a reason
- [ ] [recommended] No folder was renamed without changing what can call what

## Before Returning

- [ ] [critical] Build or type-check ran, and the result is reported honestly
- [ ] [critical] Import-direction enforcement passes; the core compiles without the framework
- [ ] [critical] Anything that depends on unverified runtime behaviour is stated as a limitation, not marked pass
- [ ] [recommended] Temporary files removed, including `.gitkeep`
