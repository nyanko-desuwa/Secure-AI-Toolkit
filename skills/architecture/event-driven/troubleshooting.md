# Event-Driven Troubleshooting

What to do when the pattern does not fit, conflicts with a constraint, or has already been applied
badly. Hazard labels E1-E9 are defined in [SKILL.md](SKILL.md).

## Everything is already an event and nobody can follow a request

Do not rewrite it in one change. Collapse per interaction, not per service:

1. List the topics with exactly one producer and one consumer that deploy together. Those are the
   collapse candidates.
2. Replace the publish/consume pair with a direct call inside one transaction. Keep the handler
   function; it becomes a normal method.
3. Delete the subscription, then the topic, then the dedupe rows for it. In that order, so nothing
   consumes a topic you removed.
4. Leave the topics with real fan-out, or with a consumer that can be down for an hour without
   anyone caring.

Report it as a reduction. "Nine of fourteen topics have one consumer that ships in the same
release" is a reviewable claim.

## Nobody can say where authorization is enforced

Resolve this before any structural change. Answer it empirically, not from the design doc:

- Grep handlers for reads of identity fields on the message: `userId`, `actor`, `role`, `tenantId`,
  `permissions`, `isAdmin`. Every hit is a candidate E1.
- For each hit, find the branch it feeds. A field that is only logged or only used as a lookup key
  is not a finding; a field that selects a code path is.
- List who can publish to each topic. If the answer is "any service in the cluster", the payload is
  attacker-controlled from the consumer's point of view even if no attacker is outside the cluster.

If the count of handlers is large, add broker-level topic ACLs first. It is the only control that
covers handlers you have not read yet. Then fix the identity reads.

## The consumer needs data it is not entitled to fetch

This is the honest tension in thin events. Options, in order:

1. Give the consumer its own credential with a narrow scope on the owning service. Usually the right
   answer and usually the one nobody asked for.
2. Have the owning service publish a projection topic containing only the fields that class of
   consumer may see, with its own ACL. Two topics, two audiences.
3. If neither is possible, keep the field in the event, restrict subscribe rights on the topic, cut
   retention, and write down that topic access is now equivalent to data access.

Do not solve it by widening the shared event. That is E2 with extra steps, and the next consumer
inherits the widening.

## Messages are disappearing

Establish where before choosing a fix.

- Check the DLQ first. A DLQ with no alert is the most common answer, and the messages are not lost
  (E6).
- Compare produced and consumed counts per topic over the same window. A gap with an empty DLQ means
  acks before processing, or a handler that swallows exceptions and returns success.
- Grep handlers for `catch` blocks that neither rethrow nor route to a DLQ. An empty catch plus an
  auto-ack is silent deletion.
- Check the ack mode. Auto-ack on delivery means a crash mid-handler loses the message with no trace.

If the answer is "we cannot tell", the first fix is a metric per topic, not a code change.

## A partition or queue has stopped moving

Almost always one message failing forever at the head (E6).

1. Read the consumer's error log for a repeating identifier. Same key, rising attempt count.
2. Decide whether it is permanent. Schema mismatch, missing referenced entity, and impossible state
   are permanent; a timeout is not.
3. Move it out of the way — dead-letter it explicitly, or on Kafka skip the offset after recording
   the key and the reason somewhere durable. Skipping without a record is data loss you chose.
4. Then fix the cap that let it retry forever.

If the stall is not one message, check consumer liveness, a handler blocked on a call with no
timeout, and a lock held across an await.

## Consumer memory grows with uptime, not with load

Growth correlated with uptime rather than throughput points at retention, not allocation.

Check in this order, cheapest first:

- Subscription registrations without matching teardown (E9). Count `on(`/`subscribe(` against
  `off(`/`unsubscribe(`/`dispose(`.
- The dedupe store, if it is in-process. A `Set` of processed IDs with no eviction grows forever, and
  grows at attacker rate if the key is caller-supplied.
- Any per-key map: correlation IDs, saga state, in-flight batches, a "seen" cache for ordering.
- Unbounded internal queues. If the queue is the leak, RSS grows during a backlog and does not fall
  after it clears, because the peak allocation is retained by the allocator.

Heap dumps, retained-size analysis, and allocation profiling belong to
`skills/architecture/performance/`. This skill tells you which structures to suspect; that one tells
you how to prove it.

## Saga instances never complete

A process manager that waits for a reply that will never arrive holds its context forever
(`CWE-772`).

- Every saga gets a timeout on creation, persisted with the instance. Not an in-process timer — a
  process restart loses those.
- Timeouts are stored as rows with a due time, and a scheduler polls them. That makes the pending
  set queryable, which is also how you find the stuck ones.
- Give the timeout path an outcome: compensate, escalate, or close as abandoned. A timeout that logs
  and returns leaves the row.
- Query for instances older than the longest legitimate duration. That number is a finding on its
  own if nobody knows it.

## Exactly-once was promised to someone

Say plainly that end-to-end exactly-once across a broker and an unrelated side effect does not
exist. What does exist:

- At-least-once delivery plus an idempotent handler, which is observationally equivalent for the
  effects you control.
- Broker-internal transactional semantics that cover reading, processing, and writing back to the
  same broker. They do not cover an HTTP call to a payment provider.

If a third party is in the path, the dedupe has to happen at the third party — an idempotency key on
their API — or you accept the duplicate and reconcile. Do not claim a guarantee you cannot enforce.

## Ordering is required across entities

Per-key ordering is achievable: partition by entity ID, one consumer per partition at a time.
Global ordering across a partitioned topic is not, and single-partition ordering caps throughput at
one consumer.

Options when the requirement is real:

1. Make the ordering constraint local by choosing the partition key to match it. Usually the
   requirement is per-customer or per-account, not global.
2. Version guard instead of ordering. If the handler is order-independent, ordering stops being a
   requirement (E5).
3. If truly global, accept one partition and one consumer, and state the throughput ceiling as a
   design limit.

## Two guides disagree

Prefer the more security-focused option and say you made the call.

- Performance material may suggest putting more into the event to avoid the callback. This skill says
  thin by default. Security wins, and the cost — one fetch per event — is stated rather than hidden.
- Framework docs may present schema-registry validation as sufficient input handling. It validates
  shape against a registered schema; it does not authorize the action or bound the values. Both are
  still yours.
- Some material treats a signed event as an authorization token. It is not (see
  [common-mistakes.md](common-mistakes.md#signing-the-event-and-calling-it-authorization)).

## The broker has no per-topic authorization

Managed buses, a shared Redis, or an in-process emitter change the tooling, not the requirement.

- Put the enforcement in the consumer. Re-authorize every action against the consumer's own store,
  which you were supposed to do anyway.
- Wrap publish and subscribe in one module so the set of topics and their producers is enumerable in
  code review.
- Keep personal data out of any topic whose subscriber set cannot be restricted.

State the residual gap: without a broker-level control, any component with connection credentials
can publish anything. That is a real limitation, not a formality.

## What you cannot verify from source

Say which of these you could not check, rather than implying you did:

- Consumer lag, queue depth, and DLQ size. Runtime state. Report the missing metric or the missing
  bound, not a number.
- Whether topic ACLs are actually applied on the running cluster. A config file or a Terraform
  module in the repository is not proof it was applied.
- Whether the redelivery window is shorter than the dedupe TTL. Both are configurable, both live
  outside application code.
- Whether the DLQ alert fires. A dashboard panel is not an alert, and an alert with no route is not
  a page.
- Whether a handler is idempotent end to end. It requires reading every write it performs, including
  the ones behind a library. If you read three of eleven, say three of eleven.

An unverified claim stated confidently is what makes a review worthless.
