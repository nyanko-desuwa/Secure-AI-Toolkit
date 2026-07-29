# Event-Driven Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable" needs a
one-line reason - an unexplained skip reads the same as an oversight.

Only run the sections the change touches. Adding one consumer to an existing topic does not need
the broker configuration section, but it does need E1, E4, and E9.

## Is the event justified at all

- [ ] The producer genuinely does not care who acts on the fact
- [ ] No caller is waiting on the result of the handler before being told "done"
- [ ] A direct call, or an outbox drained by one worker, was considered and rejected for a stated reason
- [ ] The work can complete minutes later without anyone being told something untrue
- [ ] Tracing, DLQ visibility, and a replay procedure exist before the topic does
- [ ] The topic is not a request/reply channel wearing an event's name

## E1 - Identity and authorization in the consumer

- [ ] No handler branches on a role, permission, scope, or plan tier read from the message
- [ ] `tenantId` from the payload is treated as a routing hint, never as an access grant
- [ ] The actor is re-resolved from the consumer's own store or the owning service
- [ ] The entity is loaded scoped by the re-resolved actor, not loaded then checked
- [ ] Producer identity comes from a broker-authenticated principal or a verified signature,
      not from a `source` or `service` field in the body
- [ ] A signature check, if present, is verified before parsing and is constant-time
- [ ] Signature verification failure sends the message to the DLQ; it does not log and continue
- [ ] A test publishes a forged message with an elevated `role` and asserts the handler refuses

## E2 - Payload contents

- [ ] The event carries the minimum: entity ID, event type, occurred-at, schema version
- [ ] No full entity serialised into the payload "in case a consumer needs it"
- [ ] No secret, token, session ID, password hash, or MFA seed in any field
- [ ] Personal data in the payload is justified per field, or replaced by a fetch
- [ ] The topic's retention period is known and is defensible for the data it carries
- [ ] A replay of this topic re-emitting the payload has been considered and is acceptable
- [ ] A future consumer subscribing to this topic would not thereby gain data it may not see

## E3 - Parsing

- [ ] Every event type has an explicit schema, and the handler parses against it
- [ ] No type name, class path, or discriminator in the payload selects a class to construct
- [ ] No `pickle`, `yaml.load` without `SafeLoader`, `activateDefaultTyping`, or equivalent
- [ ] Unknown fields are handled by a stated policy: ignore or reject, chosen deliberately
- [ ] Payload size is bounded before parsing, not after
- [ ] Numeric and string fields have range and length limits, not just types
- [ ] A malformed body produces a DLQ entry and a metric, not an unhandled crash loop

## E4 - Idempotency

- [ ] Delivery is documented as at-least-once; nothing in the code claims exactly-once
- [ ] Every handler with a side effect has a dedupe key derived from the event, not from `now()`
- [ ] The dedupe claim and the side effect commit in one transaction
- [ ] No check-then-act: no `SELECT` for the key followed by a separate `INSERT`
- [ ] Dedupe store has a TTL longer than the maximum redelivery window, and the number is stated
- [ ] The dedupe key is not attacker-chosen, or the store is capped per tenant if it is
- [ ] An external call that cannot be transactional passes an idempotency key downstream
- [ ] A test delivers the same event twice and asserts one side effect

## E5 - Ordering

- [ ] The ordering guarantee is written down: per-key, per-partition, or none
- [ ] Nothing depends on cross-entity ordering
- [ ] State updates carry a version or sequence and reject an older one
- [ ] Concurrency inside a partition does not silently break the per-key guarantee
- [ ] The handler is correct when a delete arrives before the create it refers to

## E6 - Failure path and DLQ

- [ ] Permanent failures (schema, authorization, not-found) go to the DLQ immediately
- [ ] Transient failures retry with a cap, jitter, and a total budget
- [ ] The retry cap is a number in code or config, not "until it works"
- [ ] A DLQ or equivalent exists for every consumer, not just for the busy ones
- [ ] Depth of the DLQ is a metric with an alert and a named owner
- [ ] A documented procedure exists for draining or replaying the DLQ
- [ ] Redrive does not re-run side effects that already succeeded (depends on E4)
- [ ] Poison-message logs record the message ID, type, and error - not the whole payload
- [ ] No secret or personal data can reach the log through the error path

## E7 - Schema evolution

- [ ] Changes are additive; no field renamed, retyped, or repurposed
- [ ] New required fields ship as a new event version, with both published during migration
- [ ] Every event carries a schema version the consumer can branch on
- [ ] Consumers deploy before producers when a new field becomes required
- [ ] An unknown event version fails closed and loudly, not silently ignored
- [ ] The set of consumers per topic is discoverable, so a breaking change can be assessed

## E8 - Broker and transport

- [ ] TLS in transit to the broker, with certificate verification enabled
- [ ] One credential per service, not one shared cluster credential
- [ ] Topic-level authorization applied: this service may publish here and read there, nothing more
- [ ] Consumer group is also authorized, not just the topic
- [ ] No permissive default that grants access when no rule matches
- [ ] Credentials come from a secret store, not from a committed config file
- [ ] Broker admin operations are not available to application credentials
- [ ] Whether these are actually applied in the running cluster is verified, or reported as unverified

## E9 - Resource lifecycle

- [ ] Every subscription registration has a matching teardown on the shutdown path
- [ ] Teardown also runs on the error path, not only on clean shutdown
- [ ] Handlers registered per request, per connection, or per tenant are removed with it
- [ ] Any in-process bus queue has a maximum size and a stated full behaviour: block, drop, reject
- [ ] Prefetch or max-in-flight is set explicitly, not left at the client default
- [ ] Retry is capped, so a failing dependency cannot become a hot loop
- [ ] The DLQ has retention or a drain job; it is not an unbounded store
- [ ] Saga and process-manager state has a timeout that fires, and the timer is durable
- [ ] Saga instances are deleted on completion and on abandonment
- [ ] No connection, transaction, or lock is held across an await that waits on the network
- [ ] Dedupe and idempotency stores have TTLs, and per-tenant caps if the key is user-influenced
- [ ] Nothing accumulates per message in a module-level map, set, or array
- [ ] Memory over uptime at flat load has been considered; growth there is the leak signal

## Before returning

- [ ] Build or compile step run
- [ ] Relevant tests run, output reported honestly
- [ ] A test asserts a forged-identity message is refused
- [ ] A test asserts double delivery causes one side effect
- [ ] A test asserts a malformed payload lands in the DLQ rather than crashing the consumer
- [ ] Every finding carries a hazard label, a location, an impact, and a residual gap
- [ ] Anything depending on runtime or broker state is labelled unverified from source
- [ ] Any recommendation to add a topic states the operational cost, not only the decoupling win
