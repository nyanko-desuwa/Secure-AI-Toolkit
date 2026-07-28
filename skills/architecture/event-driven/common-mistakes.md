# Event-Driven Common Mistakes

What goes wrong, why it goes wrong, the fix, and why the fix holds. Several entries are the wrong
fix somebody reached for after hitting an earlier one — those are the expensive ones, because they
look like progress.

## Trusting the payload because it came from the internal bus

The mistake: the handler reads `event.userId`, `event.role`, or `event.tenantId` and acts on it.

Why it happens: the broker is inside the VPC, so it feels like a trusted channel. It is a channel,
not a trust level. The message has no session, no token, and no caller context — the only thing
inside it is what some publisher wrote.

The fix: resolve the actor from the consumer's own store, check the entitlement there, and load the
entity scoped to that actor. Take producer identity from the broker's authenticated principal, never
from a `source` field in the body.

Why that works: forging the payload no longer changes the outcome, because no branch depends on it.
The worst a forged message can do is cause a lookup that fails. `A01:2025`, `CWE-863`, `CWE-602`.

## Signing the event and calling it authorization

The mistake: HMAC or JWS over the event body, signature verified in the consumer, and the handler
then trusts `role` inside the signed payload.

Why it happens: signing is real work and it does close a real gap, so it feels like the job is done.

The fix: keep the signature — it establishes integrity and producer identity. Then still re-check
the entitlement in the consumer.

Why that works: a signature answers "did this producer send this". Authorization answers "was this
producer allowed to ask for this". A compromised or buggy producer signs invalid requests perfectly.
`A08:2025` for the missing signature, `A01:2025` for the missing check. They are different holes.

## Putting the whole entity in the event

The mistake: the producer serialises the row so that "consumers have what they need".

Why it happens: it removes a callback and makes the consumer simpler. It also means nobody has to
think about which consumer may see which field.

The fix: thin event with IDs and changed-field names. Consumer fetches with its own credential.
Where the historical value genuinely matters, keep a fat event but scope the topic to entitled
consumers, cut retention, and keep personal data out of it.

Why that works: a topic with a full entity is a data store with subscribe-level access control. The
next consumer added inherits everything, and a replay re-emits it. Thin events make the entitlement
check happen on every read. `A04:2025`, `CWE-359`, `ASVS V14`.

## Logging the whole message when a handler fails

The mistake: `log.error("failed", { payload: JSON.stringify(msg) })` in the catch block, or a DLQ
wrapper that stores the body in the error record.

Why it happens: debugging a poison message without the body is hard, and the log is the obvious
place to put it.

The fix: log identifiers, type, attempt count, and the error. The body goes to the DLQ, which has
the same access controls as the topic. If you need the body in a log to debug, redact by field
allowlist rather than by pattern.

Why that works: log aggregators are usually readable by more people than the broker, retained
longer, and shipped to third parties. A refresh token or a national ID in a log has been copied
into a system nobody threat-modelled. `A09:2025`, `CWE-532`.

## Making the handler idempotent with a check-then-act

The mistake:

```typescript
const seen = await db.query("SELECT 1 FROM processed WHERE event_id = $1", [id]);
if (!seen.rowCount) { await doTheThing(); await db.query("INSERT INTO processed ..."); }
```

Why it happens: it reads like the definition of idempotency and it passes every single-threaded
test.

The fix: insert the dedupe key and perform the side effect in one transaction, and let a unique
constraint reject the duplicate.

Why that works: the check-then-act version has a window between the read and the write. Two
consumers in the same group, or one redelivery during a slow call, both pass the check. The unique
constraint is evaluated by the database at commit time, where the race does not exist. `CWE-799`.

## Dedupe table with no TTL

The mistake: idempotency is fixed, the `processed_event` table is correct, and it now has 400
million rows.

Why it happens: retention is invisible until it is a page. Nothing fails when the table grows.

The fix: a scheduled delete by `processed_at`, with an index on that column, and a retention window
longer than the broker's maximum redelivery window. Verify that window against your own broker
config — SQS message retention is configurable and defaults to 4 days, quorum queue behaviour
depends on the delivery limit and DLX you set.

Why that works: the bound becomes a number someone chose, not an accident. `CWE-401`, `CWE-770`.

Worse variant: the dedupe key is a client-supplied request ID copied into the event. Then a caller
controls how many rows exist. Cap per tenant, or derive the key server-side.

## Retry with no ceiling

The mistake: `catch { requeue(msg) }`. Or infinite retry with a fixed 1-second delay.

Why it happens: dropping a message feels worse than retrying it, and it usually is. The error is the
missing cap, not the retry.

The fix: classify permanent versus transient. Permanent goes straight to the DLQ. Transient retries
with a capped exponential backoff, jitter, and an attempt budget, then dead-letters.

Why that works: an uncapped retry against a failing dependency is a hot loop that removes the
dependency's recovery window and burns the consumer's throughput on one message. Jitter stops every
consumer retrying in the same millisecond. `A10:2025`, `CWE-400`.

## Dead-letter queue that nobody drains

The mistake: the DLQ exists, so failure handling is considered done. Nobody has looked at it since
it was created, and it holds 90 days of messages.

Why it happens: the DLQ is the end of the code path, so it feels like the end of the problem. The
happy path is green and the alert was never wired.

The fix: alert on DLQ depth and on first arrival, emit a metric tagged by event type, name an owner
per queue, set retention, and build the redrive path before you need it.

Why that works: a DLQ without alerting is a data-loss channel that reports success. The consumer
acked, the dashboard is green, and the refund never happened. `A09:2025`.

## Handlers subscribed and never unsubscribed

The mistake: `bus.on(...)` inside a request handler, a React effect, or a per-connection setup, with
no matching `off`.

Why it happens: registration is one line and teardown is three, on paths that include errors and
aborts.

The fix: pair every registration with teardown on every exit path — `close`, `error`, `aborted`,
and the normal completion. Prefer an `AbortSignal` or a disposable so the pairing is structural.

Why that works: the emitter holds a strong reference to the closure, and the closure retains
everything it captured — the request, the response, the socket. Growth is per request, not per load
spike, so it looks like a slow leak and gets blamed on the runtime. `CWE-401`. Heap-level diagnosis
is in `skills/architecture/performance/`.

## Unbounded in-memory queue between producer and consumer

The mistake: `new Queue()`, `asyncio.Queue()`, or an unbounded channel between the request path and
a background worker.

Why it happens: the default is unbounded in most libraries, and under normal load the queue is
empty, so the bound never seems to matter.

The fix: a `maxsize`, and an explicit decision about full behaviour — block the producer, drop with
a metric, or reject the request.

Why that works: an unbounded queue converts a throughput problem into an out-of-memory kill, and it
does so at the worst moment. Bounding it turns the failure into backpressure you can see and
alert on. `CWE-770` reaching `CWE-400`.

## Fixing lag by removing the bound

The mistake: the bounded queue started rejecting, so someone raised `maxsize` to 1_000_000 or
removed it.

Why it happens: rejection looks like the new bug. The bound was the messenger.

The fix: find why the consumer is slower than the producer. Usually an N+1 read per event, a
synchronous third-party call in the handler, or no batching on the write. Scale consumers, batch
writes, or shed load at the edge.

Why that works: the bound was reporting a real deficit. Raising it converts a visible rejection into
an invisible delay, then an OOM. `CWE-400`.

## Assuming ordering because it usually holds

The mistake: the handler applies `status` unconditionally, because in testing events always arrived
in order.

Why it happens: with one producer, one partition, and no retries, ordering does hold. The first
redelivery or the second partition breaks it.

The fix: a monotonic version on the event and a conditional update — `WHERE source_version < $new`.
Zero rows updated means stale; ack it.

Why that works: the guard makes ordering irrelevant instead of assumed. It also makes duplicates
harmless for state updates. `CWE-841`.

## Polymorphic deserialization for "extensibility"

The mistake: a type discriminator in the payload that selects a class —
`activateDefaultTyping`, `pickle.loads`, `yaml.load`, a `Class.forName` on a payload field.

Why it happens: it makes one event type handle many shapes with no branching, and the framework
offers it as a feature.

The fix: one explicit schema per event type, a version field, and a `switch` on the version.
Unknown types fail closed.

Why that works: the payload can no longer choose what code runs. With polymorphic typing the
attacker picks the constructor and only needs one gadget on the classpath — in a worker that often
has more network reach than the web tier. `A08:2025`, `CWE-502`.

## Using an event for something that must succeed now

The mistake: inventory reservation, payment authorization, or a permission grant published as an
event, with the API returning 200 immediately.

Why it happens: async is faster to respond and looks more scalable. The dependency did not become
optional; the failure became invisible.

The fix: do it synchronously. If the work genuinely can be deferred, respond with a state the client
can poll, not a success the system has not earned.

Why that works: telling a user "saved" before the invariant holds means overselling, double
spending, or a permission that appears seconds later. `A06:2025`.

## Adding a required field to an existing event

The mistake: the producer adds `currency` as required. Consumers deployed yesterday throw, or
default it silently.

Why it happens: the schema is treated as owned by the producer. It is a contract with every
consumer, including the ones on the previous release.

The fix: additive optional fields only. For a shape change, publish a new version alongside the old,
migrate consumers, then retire.

Why that works: a rolling deploy means both versions exist at once. A silent default is worse than
a failure, because it prices something wrong instead of stopping. `A08:2025`.

## One broker credential shared by every service

The mistake: the same username and password in every service's configuration, with no topic ACLs.

Why it happens: it is the fastest way to get the cluster working, and it is never revisited.

The fix: a principal per service, ACLs scoped to the topics and consumer groups it uses, TLS with
hostname verification, and a rotation path. Confluent's authorization documentation notes that a
resource with no ACLs is reachable only by super users by default, and that turning on
`allow.everyone.if.no.acl.found` reverses that.

Why that works: it restores the only trustworthy producer identity the consumer has, and it bounds
the blast radius of a leaked config file to one service's topics. `A02:2025`, `A07:2025`,
`CWE-522`.

## Two services that always deploy together, with a broker in between

The mistake: a broker split between two components that share a release, a team, and a schema.

Why it happens: "microservices" and "event-driven" were adopted as the target architecture rather
than as answers to a problem.

The fix: one service, one in-process call, one transaction. Keep the broker where a consumer is
genuinely independent.

Why that works: the broker cost — at-least-once, dedupe, DLQ, tracing, replay tooling — is paid
whether or not the decoupling is real. If the two sides cannot deploy independently, none of that
cost bought anything.
